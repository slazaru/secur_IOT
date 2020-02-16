import uvicorn
from fastapi import FastAPI, File, UploadFile
import os
import subprocess
from pathlib import Path

# these api endpoints are extremely insecure
# only expose this api to trusted users via SSH forwarding

# pcap uploads directory
pcapDir = "/uploads"

# make the uploads dir if it doesnt exist
p = Path(pcapDir)
p.mkdir(mode=0o755, parents=True, exist_ok=True)

app = FastAPI()

@app.get("/")
async def root():
    return {"message": "Hello World"}

# uploads a pcap, saves it, and then calls pcapreporter using the saved pcap
@app.post("/api/upload_pcap/")
async def upload_pcap(file: UploadFile = File(...)):
    try:
        # save the file to the captures directory
        newfileLocation = os.path.join(pcapDir, file.filename)
        destf = open(newfileLocation, "wb")
        destf.write(file.file.read()) # trust the user not to upload 50TB file ..
        # run pcapreporter.py
        cmd = []
        cmd.append("pcapreporter.py")
        cmd.append(newfileLocation)
        cmd.append(file.filename)
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        #p.wait()
        return {"message": "success"}
    except:
        return {"message": "failure"}

# calls pcapreporter as if on the command line
# pcapreporter interface: pcapreporter.py [pcap] [test name]
@app.get("/api/pcapreporter/")
async def pcapreporter(pcap: str="30m", name: str="UnnamedTest"):
    try:
        #print("pcap: " + pcap)
        #print("name: " + name)
        cmd = []
        cmd.append("pcapreporter.py")
        cmd.append(pcap)
        cmd.append(name)
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        #p.wait()
        return {"message": "success"}
    except:
        return {"message": "failure"}

# calls attack script as if on the command line
# attack script interface: attack.py [ip]
@app.get("/api/attack/")
async def attack(ip: str):
    try:
        cmd = []
        cmd.append("attack.py")
        cmd.append(ip)
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        #p.wait()
        return {"message": "success"}
    except Exception as e:
        print(e)
        return {"message": "failure"}

# https://www.uvicorn.org/deployment/
if __name__ == "__main__":
    uvicorn.run("main:app", host="127.0.0.1", port=8000, log_level="info")
