# NVIDIA GPU Monitoring Setup

Prometheus scrape targets for GPU metrics across your network. Linux machines
use **dcgm-exporter** (port 9400), the Windows streaming PC uses
**nvidia_gpu_exporter** (port 9835).

| Machine | IP | OS | Exporter | Port | Role |
|---|---|---|---|---|---|
| Workstation | `GPU_WORKSTATION_IP` | Linux | dcgm-exporter | 9400 | Desktop / dev |
| Streaming PC | `GPU_WINDOWS_STREAMING_IP` | Windows | nvidia_gpu_exporter | 9835 | OBS / streaming |
| LLM Server | `GPU_LLM_SERVER_IP` | Linux | dcgm-exporter | 9400 | Inference |
| Transcode Server | TBD | Linux | dcgm-exporter | 9400 | Transcoding |

---

## Linux — dcgm-exporter (Workstation, LLM Server, Transcode Server)

### Prerequisites

1. **NVIDIA drivers** installed and working (`nvidia-smi` returns output).
2. **nvidia-container-toolkit** installed so Docker can access GPUs.

```bash
# Install nvidia-container-toolkit (Debian/Ubuntu)
curl -fsSL https://nvidia.github.io/libnvidia-container/gpgkey \
  | sudo gpg --dearmor -o /usr/share/keyrings/nvidia-container-toolkit-keyring.gpg
curl -s -L https://nvidia.github.io/libnvidia-container/stable/deb/nvidia-container-toolkit.list \
  | sed 's#deb https://#deb [signed-by=/usr/share/keyrings/nvidia-container-toolkit-keyring.gpg] https://#g' \
  | sudo tee /etc/apt/sources.list.d/nvidia-container-toolkit.list
sudo apt update && sudo apt install -y nvidia-container-toolkit
sudo nvidia-ctk runtime configure --runtime=docker
sudo systemctl restart docker
```

### Deploy dcgm-exporter

Create a `docker-compose.yml` (or add to an existing one) on each Linux GPU
machine:

```yaml
services:
  dcgm-exporter:
    image: nvcr.io/nvidia/k8s/dcgm-exporter:3.3.5-3.4.1-ubuntu22.04
    container_name: dcgm-exporter
    restart: unless-stopped
    runtime: nvidia
    ports:
      - "9400:9400"
    deploy:
      resources:
        reservations:
          devices:
            - capabilities: [gpu]
    environment:
      - DCGM_EXPORTER_LISTEN=:9400
      - DCGM_EXPORTER_KUBERNETES=false
```

```bash
docker compose up -d dcgm-exporter
```

### Verify

```bash
curl http://localhost:9400/metrics | grep DCGM_FI_DEV_GPU_TEMP
```

### Key Metrics

| Metric | Description |
|---|---|
| `DCGM_FI_DEV_GPU_UTIL` | GPU utilization % |
| `DCGM_FI_DEV_GPU_TEMP` | GPU temperature °C |
| `DCGM_FI_DEV_MEM_COPY_UTIL` | Memory bandwidth utilization % |
| `DCGM_FI_DEV_FB_USED` | Framebuffer (VRAM) used (MiB) |
| `DCGM_FI_DEV_FB_FREE` | Framebuffer (VRAM) free (MiB) |
| `DCGM_FI_DEV_POWER_USAGE` | Power consumption (W) |
| `DCGM_FI_DEV_ENC_UTIL` | Video encoder utilization % |
| `DCGM_FI_DEV_DEC_UTIL` | Video decoder utilization % |
| `DCGM_FI_DEV_FAN_SPEED` | Fan speed % |
| `DCGM_FI_DEV_SM_CLOCK` | SM clock speed (MHz) |
| `DCGM_FI_DEV_MEM_CLOCK` | Memory clock speed (MHz) |
| `DCGM_FI_DEV_PCIE_TX_THROUGHPUT` | PCIe TX throughput (KB/s) |
| `DCGM_FI_DEV_PCIE_RX_THROUGHPUT` | PCIe RX throughput (KB/s) |

---

## Windows — nvidia_gpu_exporter (Streaming PC)

### Install

1. Download the latest `.exe` from
   [nvidia_gpu_exporter releases](https://github.com/utkuozdemir/nvidia_gpu_exporter/releases).
2. Place it somewhere permanent, e.g. `C:\Tools\nvidia_gpu_exporter.exe`.
3. Ensure `nvidia-smi.exe` is in your `PATH` (usually
   `C:\Program Files\NVIDIA Corporation\NVSMI\`).

### Run as a Windows Service (recommended)

Using [NSSM](https://nssm.cc/) (Non-Sucking Service Manager):

```powershell
# Download nssm from nssm.cc and extract
nssm install nvidia_gpu_exporter "C:\Tools\nvidia_gpu_exporter.exe"
nssm set nvidia_gpu_exporter AppParameters "--web.listen-address=:9835"
nssm set nvidia_gpu_exporter DisplayName "NVIDIA GPU Exporter"
nssm set nvidia_gpu_exporter Start SERVICE_AUTO_START
nssm start nvidia_gpu_exporter
```

Or run manually for testing:

```powershell
.\nvidia_gpu_exporter.exe --web.listen-address=":9835"
```

### Windows Firewall

Allow inbound TCP 9835 so Prometheus can scrape:

```powershell
New-NetFirewallRule -DisplayName "NVIDIA GPU Exporter" `
  -Direction Inbound -Protocol TCP -LocalPort 9835 -Action Allow
```

### Verify

```powershell
curl http://localhost:9835/metrics
```

### Key Metrics

| Metric | Description |
|---|---|
| `nvidia_smi_gpu_utilization_gpu` | GPU utilization % |
| `nvidia_smi_temperature_gpu` | GPU temperature °C |
| `nvidia_smi_memory_used_bytes` | VRAM used |
| `nvidia_smi_memory_total_bytes` | VRAM total |
| `nvidia_smi_power_draw_watts` | Power draw (W) |
| `nvidia_smi_fan_speed` | Fan speed % |
| `nvidia_smi_clocks_current_graphics_clock_hz` | GPU clock |
| `nvidia_smi_clocks_current_memory_clock_hz` | Memory clock |
| `nvidia_smi_encoder_utilization` | Encoder % (NVENC) |
| `nvidia_smi_decoder_utilization` | Decoder % (NVDEC) |

---

## Prometheus Configuration

Already configured in `docker/prometheus/prometheus.yml`:

- **Job `nvidia-dcgm`** — scrapes dcgm-exporter on Linux machines (port 9400)
- **Job `nvidia-gpu-windows`** — scrapes nvidia_gpu_exporter on Windows (port 9835)

Labels applied: `instance_name` (human-readable) and `gpu_role`
(desktop/inference/streaming/transcode).

After deploying exporters, reload Prometheus:

```bash
curl -X POST http://localhost:9090/-/reload
```

Verify targets at `http://SIEM_HOST:9090/targets`.

---

## Grafana Dashboard

Import the dashboard from `dashboards/nvidia_gpu_monitoring.json` in Grafana:

1. Go to **Dashboards → Import**
2. Upload the JSON file or paste its contents
3. Select your Prometheus data source

The dashboard includes panels for all machines with GPU utilization,
temperature, VRAM, power, encoder/decoder, fan speed, and clock speeds.

---

## Adding the Transcoding Server Later

When the new VLAN is ready:

1. Install NVIDIA drivers + nvidia-container-toolkit on the transcode server
2. Deploy dcgm-exporter (same Docker Compose snippet above)
3. Uncomment the transcode target in `docker/prometheus/prometheus.yml`
4. Reload Prometheus
