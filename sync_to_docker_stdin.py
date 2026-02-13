import subprocess
import os
import base64

container_id = "c995002812a8"
files_to_sync = [
    {
        'local': r"C:\Users\welerms\Projeto-teste\security_events\templates\security_events\webfilter.html",
        'container': "/app/security_events/templates/security_events/webfilter.html"
    },
    {
        'local': r"C:\Users\welerms\Projeto-teste\security_events\templates\security_events\index.html",
        'container': "/app/security_events/templates/security_events/index.html"
    },
    {
        'local': r"C:\Users\welerms\Projeto-teste\security_events\templates\security_events\ips.html",
        'container': "/app/security_events/templates/security_events/ips.html"
    },
    {
        'local': r"C:\Users\welerms\Projeto-teste\security_events\templates\security_events\antivirus.html",
        'container': "/app/security_events/templates/security_events/antivirus.html"
    },
    {
        'local': r"C:\Users\welerms\Projeto-teste\security_events\templates\security_events\pdf_report.html",
        'container': "/app/security_events/templates/security_events/pdf_report.html"
    },
    {
        'local': r"C:\Users\welerms\Projeto-teste\security_events\tasks.py",
        'container': "/app/security_events/tasks.py"
    },
    {
        'local': r"C:\Users\welerms\Projeto-teste\security_events\views.py",
        'container': "/app/security_events/views.py"
    },
    {
        'local': r"C:\Users\welerms\Projeto-teste\security_events\urls.py",
        'container': "/app/security_events/urls.py"
    },
    {
        'local': r"C:\Users\welerms\Projeto-teste\security_events\models.py",
        'container': "/app/security_events/models.py"
    },
    {
        'local': r"C:\Users\welerms\Projeto-teste\dashboard\models.py",
        'container': "/app/dashboard/models.py"
    },
    {
        'local': r"C:\Users\welerms\Projeto-teste\dashboard\admin.py",
        'container': "/app/dashboard/admin.py"
    },
    {
        'local': r"C:\Users\welerms\Projeto-teste\dashboard\views.py",
        'container': "/app/dashboard/views.py"
    },
    {
        'local': r"C:\Users\welerms\Projeto-teste\dashboard\templates\dashboard\portal.html",
        'container': "/app/dashboard/templates/dashboard/portal.html"
    },
    {
        'local': r"C:\Users\welerms\Projeto-teste\security_events\templates\security_events\webfilter.html",
        'container': "/app/security_events/templates/security_events/webfilter.html"
    },
    {
        'local': r"C:\Users\welerms\Projeto-teste\security_events\templates\security_events\index.html",
        'container': "/app/security_events/templates/security_events/index.html"
    },
    {
        'local': r"C:\Users\welerms\Projeto-teste\security_events\templates\security_events\ips.html",
        'container': "/app/security_events/templates/security_events/ips.html"
    },
    {
        'local': r"C:\Users\welerms\Projeto-teste\security_events\templates\security_events\antivirus.html",
        'container': "/app/security_events/templates/security_events/antivirus.html"
    },
    {
        'local': r"C:\Users\welerms\Projeto-teste\security_events\templates\security_events\pdf_report.html",
        'container': "/app/security_events/templates/security_events/pdf_report.html"
    },
    {
        'local': r"C:\Users\welerms\Projeto-teste\populate_modules.py",
        'container': "/app/populate_modules.py"
    }
]

for item in files_to_sync:
    local_path = item['local']
    container_path = item['container']
    
    print(f"Syncing {os.path.basename(local_path)} to {container_path}...")
    
    if not os.path.exists(local_path):
        print(f"Error: {local_path} not found.")
        continue
        
    with open(local_path, 'rb') as f:
        b64_content = base64.b64encode(f.read()).decode('utf-8')
    
    cmd = [
        "docker", "exec", "-i", container_id, 
        "python3", "-c", 
        f"import base64, sys; f=open('{container_path}', 'wb'); f.write(base64.b64decode(sys.stdin.read())); f.close()"
    ]
    
    try:
        subprocess.run(cmd, input=b64_content, check=True, capture_output=True, text=True)
        print(f"Successfully synced {os.path.basename(local_path)}")
    except subprocess.CalledProcessError as e:
        print(f"Error syncing {os.path.basename(local_path)}: {e.stderr}")

print("Sync completed.")
