import os
import json
import re
import difflib
import csv
import copy
from glob import glob
from collections import defaultdict

# Base untrusted github contexts
BASE_TAINTED = [
    'github.event.issue.title',
    'github.event.issue.body',
    'github.event.issue.pull_request',
    'github.event.pull_request.title',
    'github.event.pull_request.body',
    'github.event.comment.body',
    'github.event.review.body',
    'github.event.pages',
    'github.event.commits',
    'github.event.head_commit.message',
    'github.event.head_commit.author.email',
    'github.event.head_commit.author.name',
    'github.event.pull_request.head.ref',
    'github.event.pull_request.head.label',
    'github.event.pull_request.head.repo.default_branch',
    'github.head_ref',
    'github.base_ref',
    'github.ref_name',
    'github.ref',
]

def is_tainted(expr, tainted_vars):
    # Check if expr contains any base tainted or dynamically tainted vars
    expr = expr.strip()
    for base in BASE_TAINTED:
        if re.search(base, expr):
            return True
    
    for tvar in tainted_vars:
        # Exact match or property access
        if expr == tvar or expr.startswith(tvar + '.'):
            return True
        if tvar.endswith('.'):
            if tvar in expr:
                return True
        else:
            if re.search(r'\b' + re.escape(tvar) + r'\b', expr):
                return True
            
    return False

def parse_yaml_lines(lines):
    # A simple state machine to find run blocks and uses blocks
    # Returns a list of steps with their start and end lines, and block type
    steps = []
    
    i = 0
    while i < len(lines):
        line = lines[i]
        
        # Match uses
        uses_match = re.match(r'^(\s*)-?\s*uses:\s*(.*)$', line)
        if uses_match:
            indent = len(uses_match.group(1))
            step = {'type': 'uses', 'action': uses_match.group(2).strip(), 'start': i, 'end': i, 'with': {}}
            j = i + 1
            in_with = False
            with_indent = 0
            while j < len(lines):
                next_line = lines[j]
                if next_line.strip() == '':
                    j += 1
                    continue
                next_indent = len(next_line) - len(next_line.lstrip())
                is_comment = next_line.lstrip().startswith('#')
                if not is_comment:
                    if next_indent < indent:
                        break
                    if next_indent == indent and next_line.lstrip().startswith('-'):
                        break
                        
                id_match = re.match(r'^\s*id:\s*([a-zA-Z0-9_-]+)', next_line)
                if id_match:
                    step['id'] = id_match.group(1).strip()
                    
                if re.match(r'^\s*with:\s*$', next_line):
                    in_with = True
                    with_indent = next_indent
                elif in_with and next_indent > with_indent:
                    # Parse with key-value
                    kv_match = re.match(r'^\s*([a-zA-Z0-9_-]+):\s*(.*)$', next_line)
                    if kv_match:
                        step['with'][kv_match.group(1)] = kv_match.group(2).strip()
                j += 1
            step['end'] = j - 1
            steps.append(step)
            i = j
            continue
            
        # Match run
        run_match = re.match(r'^(\s*)-?\s*run:\s*(.*)$', line)
        if run_match:
            indent = len(run_match.group(1)) # indent of the - or the key
            key_indent = line.find('run:')
            if key_indent < 4:
                # likely a job name like 'run:', skip
                i += 1
                continue
            step = {'type': 'run', 'start': i, 'end': i, 'lines': [line]}
            j = i + 1
            in_run_value = True
            while j < len(lines):
                next_line = lines[j]
                if next_line.strip() == '':
                    if in_run_value:
                        step['lines'].append(next_line)
                    j += 1
                    continue
                next_indent = len(next_line) - len(next_line.lstrip())
                is_comment = next_line.lstrip().startswith('#')
                if not is_comment:
                    if next_indent < indent:
                        break
                    if next_indent == indent and next_line.lstrip().startswith('-'):
                        break
                    if next_indent <= key_indent and next_indent > 0:
                        in_run_value = False
                        
                id_match = re.match(r'^\s*id:\s*([a-zA-Z0-9_-]+)', next_line)
                if id_match:
                    step['id'] = id_match.group(1).strip()
                    
                if in_run_value:
                    step['lines'].append(next_line)
                    step['end'] = j
                j += 1
            step['indent'] = indent
            steps.append(step)
            i = j
            continue
            
        # Match env assignment (simplified)
        env_match = re.match(r'^(\s*)-?\s*env:\s*$', line)
        if env_match:
            indent = len(env_match.group(1))
            step = {'type': 'env', 'start': i, 'end': i, 'vars': {}}
            j = i + 1
            while j < len(lines):
                next_line = lines[j]
                if next_line.strip() == '':
                    j += 1
                    continue
                next_indent = len(next_line) - len(next_line.lstrip())
                is_comment = next_line.lstrip().startswith('#')
                if not is_comment:
                    if next_indent <= indent:
                        break
                kv_match = re.match(r'^\s*([a-zA-Z0-9_-]+):\s*(.*)$', next_line)
                if kv_match:
                    step['vars'][kv_match.group(1)] = kv_match.group(2).strip()
                j += 1
            step['end'] = j - 1
            steps.append(step)
            i = j
            continue
            
        # Match input default
        input_default_match = re.match(r'^(\s*)default:\s*(.*)$', line)
        if input_default_match:
            indent = len(input_default_match.group(1))
            val = input_default_match.group(2)
            input_name = "unknown"
            for k in range(i-1, max(-1, i-10), -1):
                prev_line = lines[k]
                prev_indent = len(prev_line) - len(prev_line.lstrip())
                if prev_indent < indent:
                    m = re.match(r'^\s*([a-zA-Z0-9_-]+):', prev_line)
                    if m:
                        input_name = m.group(1)
                        break
            
            step = {'type': 'input_default', 'name': input_name, 'value': val, 'start': i, 'end': i}
            
            if val.strip() in ('|', '>', '') or val.strip().startswith('|') or val.strip().startswith('>'):
                j = i + 1
                lines_val = []
                while j < len(lines):
                    next_line = lines[j]
                    if next_line.strip() == '':
                        j += 1
                        continue
                    next_indent = len(next_line) - len(next_line.lstrip())
                    is_comment = next_line.lstrip().startswith('#')
                    if not is_comment and next_indent <= indent:
                        break
                    lines_val.append(next_line)
                    j += 1
                step['value'] = val + '\n' + ''.join(lines_val)
                step['end'] = j - 1
                i = j - 1
                
            steps.append(step)
            i += 1
            continue
            
        i += 1
        
    return steps

def process_sample(sample_id, test_dir):
    workflow_path = os.path.join(test_dir, 'workflows', f"{sample_id}.yml")
    if not os.path.exists(workflow_path):
        workflow_path = os.path.join(test_dir, 'workflows', f"{sample_id}.yaml")
        if not os.path.exists(workflow_path):
            return [], None
            
    files_to_check = [workflow_path]
    # In a real tool we would parse the workflow and recursively find dependencies
    # For now, let's just grab all actions and reusable workflows that might be used
    actions_dir = os.path.join(test_dir, 'actions')
    reusable_dir = os.path.join(test_dir, 'reusable_workflows')
    
    # Let's map uses statements to actual files. This requires parsing the workflow
    with open(workflow_path, 'r', encoding='utf-8') as f:
        wf_content = f.read()
        
    # Find all "uses: action_path"
    uses_matches = re.findall(r'uses:\s*([^\s@]+)(?:@[^\s]+)?', wf_content)
    for u in uses_matches:
        if u.startswith('./') or not '/' in u: continue
        parts = u.split('/')
        owner = parts[0]
        repo = parts[1]
        subpath = os.sep.join(parts[2:]) if len(parts) > 2 else ''
        
        repo_dir = os.path.join(actions_dir, owner, repo)
        if os.path.exists(repo_dir):
            commits = os.listdir(repo_dir)
            if commits:
                commit = commits[0]
                action_path = os.path.join(repo_dir, commit, subpath)
                
                # Find action.yml or action.yaml in that dir (recursively or directly)
                action_files = glob(os.path.join(action_path, '**', 'action.yml'), recursive=True)
                action_files.extend(glob(os.path.join(action_path, '**', 'action.yaml'), recursive=True))
                if not action_files and os.path.exists(action_path) and os.path.isdir(action_path):
                    if os.path.exists(os.path.join(action_path, 'action.yml')):
                        action_files.append(os.path.join(action_path, 'action.yml'))
                    if os.path.exists(os.path.join(action_path, 'action.yaml')):
                        action_files.append(os.path.join(action_path, 'action.yaml'))
                        
                files_to_check.extend(action_files)
        
        # also check reusable workflows
        rw_repo_dir = os.path.join(reusable_dir, owner, repo)
        if os.path.exists(rw_repo_dir):
            commits = os.listdir(rw_repo_dir)
            if commits:
                commit = commits[0]
                rw_path = os.path.join(rw_repo_dir, commit, subpath)
                if os.path.exists(rw_path):
                    if os.path.isdir(rw_path):
                        files_to_check.extend(glob(os.path.join(rw_path, '**', '*.yml'), recursive=True))
                        files_to_check.extend(glob(os.path.join(rw_path, '**', '*.yaml'), recursive=True))
                    elif rw_path.endswith('.yml') or rw_path.endswith('.yaml'):
                        files_to_check.append(rw_path)

    vulnerabilities = []
    patches = {}
    
    print("Files to check:", files_to_check)
    
    # Global taint list for the sample execution
    tainted_vars = set()
    
    for filepath in files_to_check:
        with open(filepath, 'r', encoding='utf-8') as f:
            lines = f.readlines()
            
        rel_path = os.path.relpath(filepath, test_dir).replace('\\', '/')
        
        steps = parse_yaml_lines(lines)
        modified = False
        new_lines = list(lines)
        
        # Find new taints and sinks
        # First pass: forward flow taint tracking
        for step in steps:
            if step['type'] == 'input_default':
                exprs = re.findall(r'\$\{\{\s*([^}]+)\s*\}\}', step['value'])
                for expr in exprs:
                    if is_tainted(expr, tainted_vars):
                        tainted_vars.add(f"inputs.{step['name']}")
            elif step['type'] == 'env':
                for k, v in step['vars'].items():
                    exprs = re.findall(r'\$\{\{\s*([^}]+)\s*\}\}', v)
                    for expr in exprs:
                        if is_tainted(expr, tainted_vars):
                            tainted_vars.add(f"env.{k}")
            elif step['type'] == 'uses':
                for k, v in step['with'].items():
                    exprs = re.findall(r'\$\{\{\s*([^}]+)\s*\}\}', v)
                    for expr in exprs:
                        if is_tainted(expr, tainted_vars):
                            tainted_vars.add(f"inputs.{k}")
                            if 'id' in step:
                                tainted_vars.add(f"steps.{step['id']}.outputs.")
                                
        # Reverse order patching so line numbers don't shift during patching
        for step in reversed(steps):
            if step['type'] == 'run':
                # Check for sink
                block_text = "".join(step['lines'])
                exprs = re.finditer(r'\$\{\{\s*([^}]+)\s*\}\}', block_text)
                
                vuln_found_in_block = False
                matches = []
                for match in exprs:
                    expr = match.group(1).strip()
                    if is_tainted(expr, tainted_vars) or is_tainted(expr, []):  # Also check base taints directly
                        vuln_found_in_block = True
                        matches.append(match)
                        
                if vuln_found_in_block:
                    print("Found vuln in block!", filepath)
                    vulnerabilities.append({
                        'filepath': rel_path,
                        'start_line': step['start'] + 1,
                        'end_line': step['end'] + 1,
                    })
                    
                    # patch it
                    base_indent = step['indent']
                    env_additions = []
                    new_block_lines = list(step['lines'])
                    
                    env_vars = {}
                    for i, match in enumerate(matches):
                        expr = match.group(1).strip()
                        if expr not in env_vars:
                            var_name = f"UNTRUSTED_INPUT_{len(env_vars)}"
                            env_vars[expr] = var_name
                            # Add to env block
                            env_additions.append(f"{' ' * base_indent}env:\n")
                            env_additions.append(f"{' ' * (base_indent + 2)}{var_name}: ${{{{ {expr} }}}}\n")
                            
                    for i in range(len(new_block_lines)):
                        for expr, var_name in env_vars.items():
                            pattern_to_replace = r'\$\{\{\s*' + re.escape(expr) + r'\s*\}\}'
                            new_block_lines[i] = re.sub(pattern_to_replace, f'${var_name}', new_block_lines[i])
                            
                    # replace in new_lines
                    new_lines = new_lines[:step['start']] + env_additions + new_block_lines + new_lines[step['end']+1:]
                    modified = True

        if modified:
            patches[filepath] = (lines, new_lines)
            
    return vulnerabilities, patches

def main():
    import sys
    test_dir = None
    if len(sys.argv) > 1:
        test_dir = sys.argv[1]
    else:
        for d in ['test', 'validation', '../detect-and-fix-vulnerabilities-in-github-actions-main/test', '../detect-and-fix-vulnerabilities-in-github-actions-main/validation', '../detect-and-fix-vulnerabilities-in-github-actions-main/train']:
            if os.path.exists(d):
                test_dir = d
                break
                
    if not test_dir or not os.path.exists(test_dir):
        print("Error: Could not find dataset directory. Please provide it as an argument.")
        sys.exit(1)
        
    print(f"Using dataset directory: {test_dir}")
    workflows_dir = os.path.join(test_dir, 'workflows')
    
    if not os.path.exists(workflows_dir):
        print(f"Error: No workflows directory found in {test_dir}")
        sys.exit(1)
        
    samples = [os.path.splitext(f)[0] for f in os.listdir(workflows_dir) if f.endswith('.yml') or f.endswith('.yaml')]
    
    patches_dir = 'patches'
    os.makedirs(patches_dir, exist_ok=True)
    
    results = []
    
    for sample_id in samples:
        vulns, patch_files = process_sample(sample_id, test_dir)
        
        if vulns:
            # Sort vulns
            vulns.sort(key=lambda x: (x['filepath'], x['start_line']))
            # Keep only the FIRST sink for detection
            first_sink = vulns[0]
            # Format vulnerabilities as JSON
            vuln_obj = {
                "from": f"{test_dir.split('/')[-1]}/{first_sink['filepath']}:{first_sink['start_line']}",
                "to": f"{test_dir.split('/')[-1]}/{first_sink['filepath']}:{first_sink['end_line']}",
                "explanation": "Untrusted input used in run block"
            }
            vuln_json = json.dumps([vuln_obj])
            
            # Create patch
            patch_lines = []
            patch_json_list = []
            for filepath, (orig, new) in patch_files.items():
                rel_path = os.path.relpath(filepath, test_dir).replace('\\', '/')
                file_patch = list(difflib.unified_diff(
                    orig, new, 
                    fromfile=f"a/{rel_path}", 
                    tofile=f"b/{rel_path}",
                    n=3
                ))
                patch_lines.extend(file_patch)
                
                patch_json_list.append({
                    "file": f"{test_dir.split('/')[-1]}/{rel_path}",
                    "patch_file": f"patches/{sample_id}.patch",
                    "explanation": "Extracted untrusted input to environment variable"
                })
                
            patch_path = os.path.join(patches_dir, f"{sample_id}.patch")
            with open(patch_path, 'w', encoding='utf-8') as f:
                f.writelines(patch_lines)
                
            patch_json = json.dumps(patch_json_list)
            
            results.append({
                'sample_id': sample_id,
                'vulnerabilities': vuln_json,
                'patches': patch_json
            })
        else:
            results.append({
                'sample_id': sample_id,
                'vulnerabilities': '[]',
                'patches': '[]'
            })
            
    with open('test.csv', 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=['sample_id', 'vulnerabilities', 'patches'])
        writer.writeheader()
        writer.writerows(results)
        
    print(f"Processed {len(samples)} samples. Found vulnerabilities in {len(results)} samples.")

if __name__ == "__main__":
    main()
