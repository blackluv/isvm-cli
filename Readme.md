📘 ISVM CLI - Bitcoin Smart Contract Development Tool
The ISVM CLI provides a comprehensive toolset for developing, deploying, and interacting with smart contracts on Bitcoin using the ISVM protocol.

🚀 Installation
bash
Copy
Edit
npm install -g assemblyscript
npm install -g .
⚙️ Configuration
Set up your environment:

bash
Copy
Edit
isvm config
This will generate an isvm.config.json file with your default settings.

🔧 Core Commands
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

🧠 Advanced Commands
Command	Description
template <type>	Generate contract templates
batch --calls <json>	Execute multiple calls in one transaction
pause <address>	Pause a contract
unpause <address>	Unpause a contract
test -c <address>	Run tests against a contract

💡 Examples
📤 Deploy a Token Contract
bash
Copy
Edit
isvm deploy -f contract.wasm -a '["MyToken", "MTK", 8, 1000000]'
🔁 Call a Contract Function
bash
Copy
Edit
isvm call -c a1b2c3... -f transfer -p '["tb11234...", 100]'
👀 Watch Contract Events
bash
Copy
Edit
isvm watch a1b2c3...
📦 Batch Calls
bash
Copy
Edit
isvm batch -c '[{"contractAddress":"a1b2c3...","functionName":"transfer","params":["tb11234...",100]}]'
🌐 Environment Variables
You can override CLI config settings using environment variables:

Variable	Description
ISVM_NETWORK	mainnet / testnet / regtest
ISVM_RPC_URL	Bitcoin RPC URL (https://...)
ISVM_RPC_USER	RPC username
ISVM_RPC_PASS	RPC password
ISVM_INDEXER_URL	ISVM Indexer API (e.g. https://isvmapi.badrockinc.xyz)
ISVM_PRIVATE_KEY	WIF-format private key

🔗 Public Bitcoin Testnet RPC (Optional)
bash
Copy
Edit
https://bitcoin-testnet-rpc.publicnode.com