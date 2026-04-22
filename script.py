import os
import json
import re
import ast
import csv

def analyze_configuration(repo_path):
    config_findings = []
    for root, _, files in os.walk(repo_path):
        for file in files:
            if file.endswith('.json') and 'openclaw' in file.lower():
                file_path = os.path.join(root, file)
                try:
                    with open(file_path, 'r', encoding='utf-8') as f:
                        data = json.load(f)
                        
                        host = data.get('host', '')
                        if host == '0.0.0.0':
                            config_findings.append({
                                'File': file_path,
                                'Vulnerability': 'Insecure Network Binding (0.0.0.0)',
                                'Severity': 'Critical'
                            })
                        
                        allow_shell = data.get('allow_shell_execution', False)
                        if allow_shell is True:
                            config_findings.append({
                                'File': file_path,
                                'Vulnerability': 'Overly Permissive Execution (allow_shell_execution: true)',
                                'Severity': 'High'
                            })
                except Exception:
                    pass
    return config_findings

def analyze_python_file(file_path):
    endpoints = []
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            tree = ast.parse(f.read(), filename=file_path)
        
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef):
                is_route = False
                route_path = ""
                methods = ["GET"]
                is_authenticated = False

                for decorator in node.decorator_list:
                    if isinstance(decorator, ast.Call):
                        func_name = ""
                        if isinstance(decorator.func, ast.Attribute):
                            func_name = decorator.func.attr
                        elif isinstance(decorator.func, ast.Name):
                            func_name = decorator.func.id
                        
                        if func_name in ['route', 'get', 'post', 'put', 'delete']:
                            is_route = True
                            if func_name != 'route':
                                methods = [func_name.upper()]
                            
                            if decorator.args and isinstance(decorator.args[0], ast.Constant):
                                route_path = decorator.args[0].value
                            
                            for keyword in decorator.keywords:
                                if keyword.arg == 'methods' and isinstance(keyword.value, ast.List):
                                    methods = [elt.value for elt in keyword.value.elts if isinstance(elt, ast.Constant)]

                    elif isinstance(decorator, ast.Name):
                        if decorator.id in ['login_required', 'verify_token', 'requires_auth']:
                            is_authenticated = True

                for arg in node.args.args:
                    if 'auth' in arg.arg.lower() or 'token' in arg.arg.lower():
                        is_authenticated = True

                if is_route:
                    endpoints.append({
                        'File': file_path,
                        'Endpoint': route_path,
                        'Methods': ", ".join(methods),
                        'Authenticated': is_authenticated,
                        'Risk': 'Low' if is_authenticated else 'High (Unauthenticated Endpoint)'
                    })
    except Exception:
        pass
    return endpoints

def analyze_js_ts_file(file_path):
    endpoints = []
    route_pattern = re.compile(r'(app|router|ws)\.(get|post|put|delete|all|on)\([\'"]([^\'"]+)[\'"]')
    auth_pattern = re.compile(r'(auth|verify|login|token)', re.IGNORECASE)
    
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            lines = f.readlines()
            
        for idx, line in enumerate(lines):
            match = route_pattern.search(line)
            if match:
                method = match.group(2).upper()
                route_path = match.group(3)
                
                is_authenticated = False
                if auth_pattern.search(line):
                    is_authenticated = True
                else:
                    start_idx = max(0, idx - 3)
                    end_idx = min(len(lines), idx + 3)
                    context = "".join(lines[start_idx:end_idx])
                    if auth_pattern.search(context):
                        is_authenticated = True

                endpoints.append({
                    'File': file_path,
                    'Endpoint': route_path,
                    'Methods': method,
                    'Authenticated': is_authenticated,
                    'Risk': 'Low' if is_authenticated else 'High (Unauthenticated Endpoint)'
                })
    except Exception:
        pass
    return endpoints

def generate_attack_surface_report(repo_path, output_csv="attack_surface_report.csv"):
    all_endpoints = []
    
    for root, _, files in os.walk(repo_path):
        for file in files:
            file_path = os.path.join(root, file)
            if file.endswith('.py'):
                all_endpoints.extend(analyze_python_file(file_path))
            elif file.endswith(('.js', '.ts')):
                all_endpoints.extend(analyze_js_ts_file(file_path))
                
    config_risks = analyze_configuration(repo_path)
    
    with open(output_csv, mode='w', newline='', encoding='utf-8') as csv_file:
        fieldnames = ['Type', 'File', 'Detail', 'Methods/Vulnerability', 'Authenticated', 'Severity/Risk']
        writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
        writer.writeheader()
        
        for config in config_risks:
            writer.writerow({
                'Type': 'Configuration Risk',
                'File': config['File'],
                'Detail': 'N/A',
                'Methods/Vulnerability': config['Vulnerability'],
                'Authenticated': 'N/A',
                'Severity/Risk': config['Severity']
            })
            
        for ep in all_endpoints:
            writer.writerow({
                'Type': 'API Endpoint',
                'File': ep['File'],
                'Detail': ep['Endpoint'],
                'Methods/Vulnerability': ep['Methods'],
                'Authenticated': str(ep['Authenticated']),
                'Severity/Risk': ep['Risk']
            })
    
    print(f"Analysis complete. Report generated at: {output_csv}")

if __name__ == "__main__":
    target_directory = input("Enter the path to the OpenClaw repository: ")
    generate_attack_surface_report(target_directory)