# V2V Communication Security Simulation

This project simulates a secure Vehicle-to-Vehicle (V2V) communication system. It demonstrates the use of a Certificate Authority (CA) to provision identities, secure messaging between simulated vehicles, and a dashboard to monitor interactions and security events within the simulated environment.

## Quick Start
Run the following commands in Windows PowerShell:

**1. Create and activate the virtual environment**
```powershell
python -m venv v2v_venv
.\.venv\Scripts\Activate.ps1
```

**2. Install requirements**
```powershell
pip install -r requirments.txt
```

**3. Run the CA**
```powershell
python ca\ca.py
```

**4. Issue certs for vehicle-a and vehicle-b**
```powershell
# (Example command based on setup instructions)
python ca/issue_cert.py --vehicle-id vehicle-a --output-dir ca/certs
python ca/issue_cert.py --vehicle-id vehicle-b --output-dir ca/certs
```

**4. Verify certs for vehicle-a and vehicle-b**



**5. Start vehicle A**
```powershell
python vehicle.py --name vehicle-a --port 9001 --dashboard-port 5001
```

**6. Start vehicle B**
```powershell
python vehicle.py --name vehicle-b --port 9002 --dashboard-port 5002 --connect localhost:9001
```
