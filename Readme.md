Documentation
ISVM CLI - Bitcoin Smart Contract Development Tool
The ISVM CLI provides a comprehensive toolset for developing, deploying, and interacting with smart contracts on Bitcoin using the ISVM protocol.

Installation
bash
npm install -g assemblyscript
npm install -g .
Configuration
First configure your environment:

bash
isvm config
This will create an isvm.config.json file with your settings.

Commands
Core Commands
Command	Description
config	Configure ISVM CLI settings
compile <source>	Compile AssemblyScript to WASM
deploy -f <wasm>	Deploy a WASM contract
call -c <addr> -f <func>	Call a contract function
get <address>	Get contract information
state <address>	Get contract state
events <address>	Get contract events
watch <address>	Watch contract events in real-time
list	List deployed contracts
Advanced Commands
Command	Description
template <type>	Generate contract templates
batch --calls <json>	Execute multiple calls in one transaction
pause <address>	Pause a contract
unpause <address>	Unpause a contract
test -c <address>	Run tests against a contract
Examples
Deploy a token contract:

bash
isvm deploy -f contract.wasm -a '["MyToken", "MTK", 8, 1000000]'
Call a contract function:

bash
isvm call -c a1b2c3... -f transfer -p '["tb11234...", 100]'
Watch events:

bash
isvm watch a1b2c3...
Batch calls:

bash
isvm batch -c '[{"contractAddress":"a1b2c3...","functionName":"transfer","params":["tb11234...",100]}]'
Environment Variables
You can override config settings with env vars:

ISVM_NETWORK: mainnet/testnet/regtest

ISVM_RPC_URL: Bitcoin RPC URL

ISVM_RPC_USER: RPC username

ISVM_RPC_PASS: RPC password

ISVM_INDEXER_URL: https://isvmapi.badrockinc.xyz

ISVM_PRIVATE_KEY: WIF private key

https://bitcoin-testnet-rpc.publicnode.com