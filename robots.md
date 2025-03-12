# NSYS:COMPRESSED

## CMPNTS|TYPE|DEPS|CRITICAL
Launcher|Orchestrator|BE,FE|start_services()
BackendAPI|FastAPI|ScannerSvc,NetDetector|/discover, /scan
FrontendWeb|Flask|JS,WebSocket|render_dashboard()
ScannerService|Class|Device,Service|discover_network()
NetworkDetector|Class|ARP,Ping|arp_scan(), ping_sweep()
EventBus|PubSub||publish(), subscribe()
JSONStore|Data|Devices,Services|CRUD ops

## CLI_ARGS|TYPE|DEFAULT
--host|str|127.0.0.1
--api-port|int|8000
--web-port|int|5002
--debug|bool|False
--no-browser|bool|False
--wait-for-api|bool|False
--api-timeout|int|30

## API_ENDPOINTS|METHOD|PATH|PARAMS|PURPOSE
discover|GET|/discover||Network scan
services|GET|/services/{ip}||Service enum
health|GET|/health||Status check

## ERR_CODES|MEANING
PORT_CONFLICT|Port in use
DEPS_MISSING|Requirements not met
API_TIMEOUT|Backend init failed

## CFG_HIERARCHY
1. CLI_ARGS
2. ENV_VARS
3. config/default.yml
4. config/data_store.yml

## DATA_SCHEMAS
Devices@/schemas/device.json
Services@/schemas/service.json
Fingerprints@/schemas/fingerprint.json

## LIFE_CYCLE
BOOT: DepCheck→PortVerify→StartBE→StartFE→HealthCheck
SHUTDOWN: SigHandler→KillProcs→PortRelease→Cleanup
