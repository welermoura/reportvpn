import subprocess
import os
import base64

container_id = "c995002812a8"
# Get current directory
cwd = os.getcwd()
print(f"Current working directory: {cwd}")

files_to_sync = [
    'index.html',
    'ips.html',
    'webfilter.html'
]

# Search for the directory to be sure
target_dir = None
for root, dirs, files in os.walk(cwd):
    if 'security_events' in dirs:
        potential_dir = os.path.join(root, 'security_events', 'templates', 'security_events')
        if os.path.exists(potential_dir):
            target_dir = potential_dir
            break

if not target_dir:
    print("Error: Could not find templates directory.")
    exit(1)

print(f"Using templates directory: {target_dir}")

for filename in files_to_sync:
    local_path = os.path.join(target_dir, filename)
    container_path = f"/app/security_events/templates/security_events/{filename}"
    
    if not os.path.exists(local_path):
        print(f"Error: {local_path} not found.")
        continue
        
    print(f"Syncing {filename} to container path {container_path}...")
    
    with open(local_path, 'rb') as f:
        data = f.read()
        b64_content = base64.b64encode(data).decode('utf-8')
    
    # Use sh -c "echo ... | base64 -d > ..." inside the container
    # Redirecting stderr to catch errors
    cmd = [
        "docker", "exec", container_id, 
        "sh", "-c", 
        f"echo {b64_content} | base64 -d > {container_path}"
    ]
    
    try:
        result = subprocess.run(cmd, check=True, capture_output=True, text=True)
        print(f"Successfully synced {filename}")
    except subprocess.CalledProcessError as e:
        print(f"Error syncing {filename}: {e.stderr}")

print("Sync completed.")
