import subprocess
import os

container_id = "c995002812a8"
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
    
    with open(local_path, 'r', encoding='utf-8') as f:
        content = f.read()
    
    # Escape single quotes for the python -c command
    escaped_content = content.replace("'", "'\"'\"'")
    
    # Use python inside the container to write the file
    # This avoids shell redirection and piping issues
    cmd = [
        "docker", "exec", container_id, 
        "python3", "-c", 
        f"with open('{container_path}', 'w') as f: f.write('''{escaped_content}''')"
    ]
    
    try:
        subprocess.run(cmd, check=True, capture_output=True, text=True)
        print(f"Successfully synced {filename}")
    except subprocess.CalledProcessError as e:
        print(f"Error syncing {filename}: {e.stderr}")

print("Sync completed.")
