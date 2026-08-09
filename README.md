# oracle-cloud-instances

My scripts to manage OCI free tier instances

```
git clone https://github.com/FlippFuzz/oracle-cloud-instances

# Move files such as your pem file and config.yaml to oracle-cloud-instances directory

cd oracle-cloud-instances
python3 -m venv venv
source venv/bin/activate
pip install --upgrade -r requirements.txt

# Optional logfire setup
logfire auth
logfire projects use starter-project

# Run
python task_update_instances.py
```
