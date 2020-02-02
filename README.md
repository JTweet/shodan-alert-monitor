# shodan alert monitor
A simple application to log banners received from the shodan API. Requires a shodan API key and configured alerts.

## Usage
Ensure you have installed the shodan python client, then copy and modify the configuration.json.dist file. To view your alert IDs, please use the shodan command line interface.

```
tweet@host# shodan alert list
# Alert ID          Name            IP/ Network
TH1S1SAN3X4MPL31    Monitornet      192.0.2.0/24 Triggers: malware, open_database, iot, uncommon, internet_scanner, industrial_control_system, new_service, ssl_expired, vulnerable
```

Run the monitoring script
```
tweet@host# ./shodan-alert-monitor.py configuration.json
```