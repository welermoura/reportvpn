import subprocess
import os
import base64

container_id = "c995002812a8"
# Using absolute path with raw string
templates_dir = r"C:\Users\welerms\Projeto-teste\security_events\templates\security_events"

files_to_sync = [
    'index.html',
    'ips.html',
    'webfilter.html'
]

for filename in files_to_sync:
    local_path = os.path.join(templates_dir, filename)
    container_path = f"/app/security_events/templates/security_events/{filename}"
    
    print(f"Syncing {filename} to container...")
    
    if not os.path.exists(local_path):
        print(f"Error: {local_path} not found.")
        continue
        
    with open(local_path, 'rb') as f:
        b64_content = base64.b64encode(f.read()).decode('utf-8')
    
    # Use sh -c "echo ... | base64 -d > ..." inside the container
    cmd = [
        "docker", "exec", container_id, 
        "sh", "-c", 
        f"echo {b64_content} | base64 -d > {container_path}"
    ]
    
    try:
        subprocess.run(cmd, check=True, capture_output=True, text=True)
        print(f"Successfully synced {filename}")
    except subprocess.CalledProcessError as e:
        print(f"Error syncing {filename}: {e.stderr}")

print("Sync completed.")
