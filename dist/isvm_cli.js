#!/usr/bin/env -S node --experimental-global-webcrypto
//import './crypto-setup';
import { Command } from 'commander';
import * as fs from 'fs';
import * as path from 'path';
import * as crypto from 'crypto';
import axios from 'axios';
import * as bitcoin from 'bitcoinjs-lib';
import * as ecc from 'tiny-secp256k1';
import { ECPairFactory } from 'ecpair';
import chalk from 'chalk';
import ora from 'ora';
import inquirer from 'inquirer';
import Table from 'cli-table3';
import WebSocket from 'ws';
import * as BTON from '@cmdcode/bton';
import { KeyPair } from '@cmdcode/crypto-utils';
// Initialize Bitcoin library
bitcoin.initEccLib(ecc);
const ECPair = ECPairFactory(ecc);
class ISVMError extends Error {
    code;
    constructor(message, code) {
        super(message);
        this.code = code;
        this.name = 'ISVMError';
    }
    static ERROR_CODES = {
        INVALID_CONSTRUCTOR_ARGS: 'INVALID_CONSTRUCTOR_ARGS',
        BATCH_CALL_LIMIT_EXCEEDED: 'BATCH_CALL_LIMIT_EXCEEDED',
        CONTRACT_PAUSED: 'CONTRACT_PAUSED',
        // ... other error codes that match indexer ...
    };
}
const ISVM_OPS = {
    DEPLOY: 0x01,
    CALL: 0x02,
    BATCH: 0x03,
    PREFIX: Buffer.from('ISVM')
};
const MAX_OP_RETURN_SIZE = 80;
const MAX_BATCH_CALLS = 10;
const DEFAULT_FEE_RATE = 50; // sat/byte
class ISVMCLI {
    config;
    keyPair;
    network;
    constructor() {
        this.loadConfig();
        this.network = this.getNetwork();
        if (this.config.privateKey) {
            this.keyPair = ECPair.fromWIF(this.config.privateKey, this.network);
        }
    }
    loadConfig() {
        const configPath = path.join(process.cwd(), 'isvm.config.json');
        try {
            const configData = fs.readFileSync(configPath, 'utf8');
            this.config = JSON.parse(configData);
        }
        catch (error) {
            this.config = {
                network: 'testnet',
                rpcUrl: 'http://localhost:18332',
                rpcUser: 'user',
                rpcPassword: 'password',
                indexerUrl: 'http://localhost:3000'
            };
        }
    }
    getNetwork() {
        switch (this.config.network) {
            case 'mainnet': return bitcoin.networks.bitcoin;
            case 'testnet': return bitcoin.networks.testnet;
            case 'regtest': return bitcoin.networks.regtest;
            default: return bitcoin.networks.testnet;
        }
    }
    async rpcCall(method, params = []) {
        try {
            const response = await axios.post(this.config.rpcUrl, {
                jsonrpc: '2.0',
                id: Date.now(),
                method,
                params
            }, {
                auth: {
                    username: this.config.rpcUser,
                    password: this.config.rpcPassword
                }
            });
            if (response.data.error) {
                throw new ISVMError(`RPC Error: ${response.data.error.message}`, 'RPC_ERROR');
            }
            return response.data.result;
        }
        catch (error) {
            if (axios.isAxiosError(error)) {
                const axiosError = error;
                const status = axiosError.response?.status ?? 'Unknown';
                throw new ISVMError(`HTTP Error: ${status}`, 'HTTP_ERROR');
            }
            if (error instanceof Error) {
                throw new ISVMError(`Unexpected Error: ${error.message}`, 'UNKNOWN_ERROR');
            }
            throw new ISVMError(`Unknown Error: ${String(error)}`, 'UNKNOWN_ERROR');
        }
    }
    async indexerCall(endpoint, options = {}) {
        try {
            const response = await axios.get(`${this.config.indexerUrl}${endpoint}`, options);
            return response.data;
        }
        catch (error) {
            throw new ISVMError(`Indexer Error: ${error.message}`, 'INDEXER_ERROR');
        }
    }
    computeContractAddress(deployerAddress, commitTxId, salt = "0") {
        // For temp calculations during deployment prep, return a placeholder
        if (commitTxId === 'tempTxId') {
            return '0'.repeat(40); // 40 character hex placeholder (20 bytes)
        }
        const input = deployerAddress + commitTxId + salt;
        return crypto.createHash('sha256').update(input).digest('hex').slice(0, 40);
    }
    /*private createOpReturnData(type: number, data: Buffer): Buffer {
      const header = Buffer.from('ISVM', 'utf8');
      const typeBuffer = Buffer.from([type]);
      return Buffer.concat([header, typeBuffer, data]);
    }*/
    async compressWasm(wasmBytes) {
        const zlib = await import('zlib');
        return zlib.gzipSync(wasmBytes);
    }
    /*private createDeploymentData(deployment: ContractDeployment): Buffer {
    const deployerAddress = bitcoin.address.toOutputScript(this.config.address!, this.network);
    const deployerHash = bitcoin.crypto.hash160(deployerAddress);
    const contractAddr = this.computeContractAddress(deployerHash.toString('hex'), 'tempTxId', deployment.salt);
    
    // Convert constructor args to Buffer with proper encoding
    let argsBuffer = Buffer.alloc(0);
    if (deployment.constructorArgs.length > 0) {
      argsBuffer = Buffer.from(JSON.stringify(deployment.constructorArgs), 'utf8');
      if (argsBuffer.length > 49) {
        throw new ISVMError('Constructor args too large', 'ARGS_TOO_LARGE');
      }
    }
  
    const timelockBuffer = Buffer.alloc(4);
    timelockBuffer.writeUInt32BE(deployment.timelock || 0);
  
    return Buffer.concat([
      Buffer.from(contractAddr, 'hex'),
      Buffer.from([deployment.flags]),
      timelockBuffer,
      argsBuffer
    ]);
  }*/
    createDeploymentData(deployment, actualCommitTxId) {
        // Get the deployer address as hex string
        const deployerAddress = this.config.address;
        // Use actual commit transaction ID if provided, otherwise use temp for pre-calculation
        const commitTxId = actualCommitTxId || 'tempTxId';
        const contractAddr = this.computeContractAddress(deployerAddress, commitTxId, deployment.salt);
        // Convert constructor args to Buffer with proper encoding
        let argsBuffer = Buffer.alloc(0);
        if (deployment.constructorArgs && deployment.constructorArgs.length > 0) {
            // Add some metadata before the JSON (to match your parser's expectation)
            const metadataBuffer = Buffer.from([0x6c, 0x54, 0x99, 0x2e, 0x6d, 0x1e, 0x32]); // 7 bytes
            const paddingBuffer = Buffer.alloc(4, 0x00); // 4 zero bytes
            const jsonBuffer = Buffer.from(JSON.stringify(deployment.constructorArgs), 'utf8');
            argsBuffer = Buffer.concat([
                metadataBuffer,
                paddingBuffer,
                jsonBuffer
            ]);
            if (argsBuffer.length > 49) {
                throw new ISVMError('Constructor args too large', 'ARGS_TOO_LARGE');
            }
        }
        const timelockBuffer = Buffer.alloc(4);
        timelockBuffer.writeUInt32BE(deployment.timelock || 0);
        const deploymentData = Buffer.concat([
            Buffer.from(contractAddr, 'hex'), // 20 bytes (contract address - first 20 bytes of 40 char hex)
            Buffer.from([deployment.flags || 0]), // 1 byte (flags)
            timelockBuffer, // 4 bytes (timelock)
            argsBuffer // Variable length args
        ]);
        return deploymentData;
    }
    isValidContractAddress(address) {
        return /^[0-9a-f]{40}$/.test(address);
    }
    createCallData(call) {
        const paramsBuffer = Buffer.alloc(50);
        const paramsJson = JSON.stringify(call.params);
        console.log('Params JSON size:', paramsJson.length);
        Buffer.from(paramsJson).copy(paramsBuffer, 0, 0, 49); // Leave 1 byte padding
        return Buffer.concat([
            Buffer.from(call.contractAddress, 'hex'), // 20 bytes
            Buffer.from(call.funcHash, 'hex'), // 4 bytes
            paramsBuffer // 50 bytes
        ]);
    }
    /*private createOpReturn(type: number, data: Buffer): Buffer {
      const buffer = Buffer.concat([
        ISVM_OPS.PREFIX,   // 4 bytes
        Buffer.from([type]), // 1 byte
        data               // Variable (75 bytes max)
      ]);
  
      if (buffer.length > 80) {
        throw new ISVMError(
          'OP_RETURN_OVERFLOW',
          `OP_RETURN exceeds 80 bytes (${buffer.length})`
        );
      }
  
      return buffer;
    }*/
    createOpReturn(type, data) {
        // Create the payload components
        const prefix = Buffer.from('ISVM', 'utf8'); // 4 bytes
        const typeByte = Buffer.from([type]); // 1 byte
        // Combine all payload parts
        const payload = Buffer.concat([
            prefix, // "ISVM" (4 bytes)
            typeByte, // type (1 byte)
            data // actual data
        ]);
        // Validate payload size (max 80 bytes)
        if (payload.length > 80) {
            throw new ISVMError('OP_RETURN_OVERFLOW', `Payload exceeds 80 bytes (${payload.length})`);
        }
        // Create the final script
        return Buffer.concat([
            Buffer.from([0x6a]), // OP_RETURN
            Buffer.from([payload.length]), // Length byte
            payload // Actual payload
        ]);
    }
    createChunkedData(type, data, chunkSize = 900) {
        const chunks = [];
        const totalChunks = Math.ceil(data.length / chunkSize);
        for (let i = 0; i < totalChunks; i++) {
            const start = i * chunkSize;
            const end = Math.min(start + chunkSize, data.length);
            const chunkData = data.subarray(start, end);
            const chunkHeader = Buffer.alloc(5);
            chunkHeader.writeUInt8(type, 0); // Operation type
            chunkHeader.writeUInt16BE(totalChunks, 1); // Total chunks
            chunkHeader.writeUInt16BE(i + 1, 3); // Current chunk number
            chunks.push(Buffer.concat([
                ISVM_OPS.PREFIX,
                Buffer.from([0x06]), // OP_CHUNKED = 0x06
                chunkHeader,
                chunkData
            ]));
        }
        return chunks;
    }
    async sendChunkedTransaction(data, isCompressed = false) {
        if (!this.keyPair)
            throw new ISVMError('Private key not configured', 'NO_PRIVATE_KEY');
        const spinner = ora('Preparing chunked transaction...').start();
        try {
            // Compress if not already compressed
            const processedData = isCompressed ? data : await this.compressWasm(data);
            const chunks = this.createChunkedData(0x01, processedData); // 0x01 for deployment data
            const utxos = await this.rpcCall('listunspent', [1, 9999999, [this.config.address]]);
            if (utxos.length === 0)
                throw new ISVMError('No UTXOs available', 'NO_UTXOS');
            const psbt = new bitcoin.Psbt({ network: this.network });
            let totalInput = 0;
            // Add inputs (use up to 5 UTXOs)
            for (const utxo of utxos.slice(0, 5)) {
                psbt.addInput({
                    hash: utxo.txid,
                    index: utxo.vout,
                    witnessUtxo: {
                        script: Buffer.from(utxo.scriptPubKey, 'hex'),
                        value: Math.floor(utxo.amount * 100000000)
                    }
                });
                totalInput += Math.floor(utxo.amount * 100000000);
            }
            // Add chunk outputs
            for (const chunk of chunks) {
                psbt.addOutput({
                    script: bitcoin.script.compile([
                        bitcoin.opcodes.OP_RETURN,
                        chunk
                    ]),
                    value: 0
                });
            }
            // Add change output
            const feeRate = await this.rpcCall('estimatesmartfee', [1]);
            const satPerByte = feeRate.feerate ? Math.ceil(feeRate.feerate * 100000) : 20;
            const estimatedSize = 150 * psbt.inputCount + chunks.reduce((sum, c) => sum + c.length, 0);
            const fee = estimatedSize * satPerByte;
            const changeAmount = totalInput - fee;
            if (changeAmount > 546) {
                psbt.addOutput({
                    address: this.config.address,
                    value: changeAmount
                });
            }
            // Sign and broadcast
            spinner.text = 'Signing transaction...';
            for (let i = 0; i < psbt.inputCount; i++) {
                psbt.signInput(i, this.keyPair);
            }
            psbt.finalizeAllInputs();
            spinner.text = 'Broadcasting transaction...';
            const txHex = psbt.extractTransaction().toHex();
            const txId = await this.rpcCall('sendrawtransaction', [txHex]);
            spinner.succeed('Chunked transaction submitted successfully');
            return txId;
        }
        catch (error) {
            spinner.fail('Chunked transaction failed');
            throw error;
        }
    }
    async deployLarge(deployment) {
        const wasmBytes = fs.readFileSync(deployment.wasmPath);
        const compressedWasm = this.compressWasm(wasmBytes);
        const deploymentData = this.createDeploymentData(deployment);
        const combinedData = Buffer.concat([
            Buffer.from([0x01]), // Deployment type marker
            deploymentData
        ]);
        // Automatically use chunking if over 900 bytes
        if (combinedData.length > 900) {
            return this.sendChunkedTransaction(combinedData, false);
        }
        // Original deployment logic for small contracts
        return this.deploy(deployment);
    }
    /*async callLarge(functionCall: FunctionCall): Promise<string> {
      const spinner = ora('Calling contract function (batch)...').start();
    
      console.log('here')
      
      try {
        // Create batch call data in the same format the indexer expects
        const paramsJson = JSON.stringify(functionCall.params);
        const paramsBuffer = Buffer.from(paramsJson, 'utf8');
        
        const functionHash = crypto.createHash('sha256')
          .update(functionCall.functionName)
          .digest()
          .slice(0, 4);
        
        // Create single call data for batch (since we only have one call)
        const singleCallData = Buffer.concat([
          Buffer.from(functionCall.contractAddress, 'hex'), // 20 bytes contract address
          functionHash,                                      // 4 bytes function hash
          paramsBuffer                                       // variable length params
        ]);
    
        console.log('here2')
        
        // Create batch call data with OP_BATCH opcode
        const batchCallData = Buffer.concat([
          Buffer.from([0x02]), // Batch call count (1 call)
          singleCallData       // The single call data
        ]);
    
        console.log('here3')
        
        // Create OP_RETURN with batch data
        const batchOpReturn = this.createOpReturn(ISVM_OPS.BATCH, batchCallData);
    
        console.log('here4')
        
        // Get UTXOs
        const utxos = await this.fetchUtxos(this.config.address!);
        if (utxos.length === 0) {
          throw new ISVMError('No UTXOs available', 'NO_UTXOS');
        }
        
        // Create PSBT
        const psbt = new bitcoin.Psbt({ network: this.network });
        const utxo = utxos[0];
        
        psbt.addInput({
          hash: utxo.txid,
          index: utxo.vout,
          witnessUtxo: {
            script: this.getScriptPubKey(this.config.address!),
            value: utxo.value
          }
        });
        
        // Add OP_RETURN output with batch data
        psbt.addOutput({
          script: bitcoin.script.compile([
            bitcoin.opcodes.OP_RETURN,
            batchOpReturn
          ]),
          value: 0
        });
        
        // Add change output
        const estimatedSize = 150 + batchOpReturn.length;
        const fee = estimatedSize * DEFAULT_FEE_RATE;
        const changeAmount = utxo.value - fee;
        
        if (changeAmount > 546) {
          psbt.addOutput({
            address: this.config.address!,
            value: changeAmount
          });
        }
        
        // Sign and broadcast
        psbt.signInput(0, this.keyPair);
        psbt.finalizeAllInputs();
        const txHex = psbt.extractTransaction().toHex();
        
        const result = await this.broadcastTransaction(txHex);
        spinner.succeed('Batch function call completed');
        return result;
        
      } catch (error) {
        spinner.fail('Batch function call failed');
        throw error;
      }
    }*/
    async callLarge(functionCall) {
        const spinner = ora('Calling contract function (chunked)...').start();
        try {
            // Prepare the full payload for chunking
            const paramsJson = JSON.stringify(functionCall.params);
            const paramsBuffer = Buffer.from(paramsJson, 'utf8');
            const functionHash = crypto.createHash('sha256')
                .update(functionCall.functionName)
                .digest()
                .slice(0, 4);
            // Create the full function call data
            const fullCallData = Buffer.concat([
                Buffer.from([0x02]), // Data type: Function call
                Buffer.from(functionCall.contractAddress, 'hex'), // 20 bytes contract address
                functionHash, // 4 bytes function hash  
                paramsBuffer // variable length params
            ]);
            // Calculate chunk size accounting for ALL overhead:
            // OP_RETURN overhead: 7 bytes (ISVM prefix + type + OP_RETURN + length)
            // Chunking header: 8 bytes (4 batch ID + 2 total + 2 current)
            // Available space: 80 - 7 - 8 = 65 bytes
            const maxChunkSize = 65;
            const chunks = this.chunkData(fullCallData, maxChunkSize);
            console.log(`Splitting data into ${chunks.length} chunks`);
            // Generate unique batch ID for this chunked transaction
            const batchId = crypto.randomBytes(4);
            // Send chunks sequentially, waiting for each to be confirmed
            const chunkTxIds = [];
            for (let i = 0; i < chunks.length; i++) {
                spinner.text = `Sending chunk ${i + 1}/${chunks.length}...`;
                // Create consistent header structure (4 bytes batch ID + 2 bytes total + 2 bytes current + data)
                const chunkHeader = Buffer.concat([
                    batchId, // 4 bytes batch ID
                    Buffer.from([0, chunks.length]), // 2 bytes total chunks (big-endian)
                    Buffer.from([0, i + 1]), // 2 bytes current chunk (big-endian, 1-based)
                    chunks[i] // Chunk data
                ]);
                const chunkOpReturn = this.createOpReturn(ISVM_OPS.BATCH, chunkHeader);
                const chunkTxId = await this.sendChunkTransactionWithWait(chunkOpReturn);
                chunkTxIds.push(chunkTxId);
                if (i < chunks.length - 1) {
                    spinner.text = `Waiting for chunk ${i + 1} to be confirmed...`;
                    await this.waitForTxConfirmation(chunkTxId, 1); // Wait for 1 confirmation
                    await this.delay(2000); // Additional delay
                }
            }
            spinner.succeed(`Chunked function call completed. Sent ${chunks.length} chunks.`);
            return chunkTxIds[chunkTxIds.length - 1];
        }
        catch (error) {
            spinner.fail('Chunked function call failed');
            throw error;
        }
    }
    chunkData(data, chunkSize) {
        const chunks = [];
        let offset = 0;
        while (offset < data.length) {
            const remainingBytes = data.length - offset;
            const currentChunkSize = Math.min(chunkSize, remainingBytes);
            const chunk = data.subarray(offset, offset + currentChunkSize);
            chunks.push(chunk);
            offset += currentChunkSize;
        }
        return chunks;
    }
    async sendChunkTransactionWithWait(opReturnData) {
        let retries = 0;
        const maxRetries = 3;
        while (retries < maxRetries) {
            try {
                const utxos = await this.fetchUtxos(this.config.address);
                if (utxos.length === 0) {
                    throw new ISVMError('No UTXOs available', 'NO_UTXOS');
                }
                // Use the first available UTXO
                const utxo = utxos[0];
                console.log('OpReturn data length:', opReturnData.length);
                const psbt = new bitcoin.Psbt({ network: this.network });
                psbt.addInput({
                    hash: utxo.txid,
                    index: utxo.vout,
                    witnessUtxo: {
                        script: this.getScriptPubKey(this.config.address),
                        value: utxo.value
                    }
                });
                const actualData = opReturnData.slice(2);
                // Now create a proper OP_RETURN script
                const opReturnScript = bitcoin.script.compile([
                    bitcoin.opcodes.OP_RETURN,
                    actualData
                ]);
                psbt.addOutput({
                    script: opReturnScript,
                    value: 0
                });
                const estimatedSize = 150 + opReturnData.length;
                const fee = Math.max(estimatedSize * DEFAULT_FEE_RATE, 1000);
                const changeAmount = utxo.value - fee;
                if (changeAmount > 546) {
                    psbt.addOutput({
                        address: this.config.address,
                        value: changeAmount
                    });
                }
                psbt.signInput(0, this.keyPair);
                psbt.finalizeAllInputs();
                const txHex = psbt.extractTransaction().toHex();
                return await this.broadcastTransaction(txHex);
            }
            catch (error) {
                retries++;
                if (retries >= maxRetries) {
                    throw error;
                }
                // Wait before retry
                await this.delay(5000);
            }
        }
        throw new Error('Max retries exceeded');
    }
    delay(ms) {
        return new Promise(resolve => setTimeout(resolve, ms));
    }
    compressData(data) {
        const zlib = require('zlib');
        return zlib.gzipSync(data, {
            level: zlib.constants.Z_BEST_COMPRESSION
        });
    }
    async fetchUtxos(address) {
        const networkPrefix = this.config.network === 'mainnet' ? '' : 'testnet/';
        const url = `https://mempool.space/${networkPrefix}api/address/${address}/utxo`;
        try {
            const response = await axios.get(url);
            return response.data.map((utxo) => ({
                txid: utxo.txid,
                vout: utxo.vout,
                value: utxo.value,
                //scriptPubKey: utxo.scriptPubKey // May need to construct this from address
            }));
        }
        catch (error) {
            throw new ISVMError(`Failed to fetch UTXOs: ${error.message}`, 'UTXO_FETCH_ERROR');
        }
    }
    getScriptPubKey(address) {
        try {
            // Convert address to output script
            return bitcoin.address.toOutputScript(address, this.network);
        }
        catch (error) {
            throw new ISVMError(`Invalid address format: ${address}`, 'INVALID_ADDRESS');
        }
    }
    decompressData(data) {
        const zlib = require('zlib');
        return zlib.gunzipSync(data);
    }
    createPauseData(contractAddress, pause) {
        if (!this.isValidContractAddress(contractAddress)) {
            throw new ISVMError(`Invalid contract address: ${contractAddress}`, 'INVALID_ADDRESS');
        }
        return Buffer.concat([
            Buffer.from(contractAddress, 'hex'), // 20 bytes
            Buffer.from([pause ? 0x01 : 0x00]) // 1 byte flag (0x01 = pause, 0x00 = unpause)
        ]);
    }
    async pauseContract(contractAddress, pause) {
        if (!this.keyPair) {
            throw new ISVMError('Private key not configured. Run `isvm config` first.', 'NO_PRIVATE_KEY');
        }
        const action = pause ? 'Pausing' : 'Unpausing';
        const spinner = ora(`${action} contract...`).start();
        try {
            // 1. Create pause/unpause OP_RETURN data
            const pauseData = this.createPauseData(contractAddress, pause);
            const pauseOpReturn = this.createOpReturn(0x05, pauseData); // OP_PAUSE = 0x05
            // 2. Get UTXOs
            const utxos = await this.rpcCall('listunspent', [1, 9999999, [this.config.address]]);
            if (utxos.length === 0) {
                throw new ISVMError('No UTXOs available for transaction', 'NO_UTXOS');
            }
            // 3. Create PSBT
            const psbt = new bitcoin.Psbt({ network: this.network });
            // Add input (use first UTXO)
            const utxo = utxos[0];
            psbt.addInput({
                hash: utxo.txid,
                index: utxo.vout,
                witnessUtxo: {
                    script: Buffer.from(utxo.scriptPubKey, 'hex'),
                    value: Math.floor(utxo.amount * 100000000)
                }
            });
            // Add pause output
            psbt.addOutput({
                script: bitcoin.script.compile([
                    bitcoin.opcodes.OP_RETURN,
                    pauseOpReturn
                ]),
                value: 0
            });
            // 4. Estimate fee and add change
            const feeRate = await this.rpcCall('estimatesmartfee', [1]);
            const satPerByte = feeRate.feerate ? Math.ceil(feeRate.feerate * 100000) : 20;
            const estimatedSize = 150 + pauseOpReturn.length;
            const fee = estimatedSize * satPerByte;
            const changeAmount = Math.floor(utxo.amount * 100000000) - fee;
            if (changeAmount > 546) { // Dust limit
                psbt.addOutput({
                    address: this.config.address,
                    value: changeAmount
                });
            }
            else if (changeAmount < 0) {
                throw new ISVMError('Insufficient funds for transaction', 'INSUFFICIENT_FUNDS');
            }
            // 5. Sign and broadcast
            spinner.text = 'Signing transaction...';
            psbt.signInput(0, this.keyPair);
            psbt.finalizeAllInputs();
            spinner.text = 'Broadcasting transaction...';
            const txHex = psbt.extractTransaction().toHex();
            const txId = await this.rpcCall('sendrawtransaction', [txHex]);
            spinner.succeed(`Contract ${pause ? 'paused' : 'unpaused'} successfully!`);
            console.log(chalk.green(`Transaction ID: ${txId}`));
            return txId;
        }
        catch (error) {
            spinner.fail(`${pause ? 'Pause' : 'Unpause'} failed`);
            throw error;
        }
    }
    async getUtxoDetails(txid, vout) {
        const networkPrefix = this.config.network === 'mainnet' ? '' : 'testnet/';
        const txUrl = `https://mempool.space/${networkPrefix}api/tx/${txid}`;
        try {
            const response = await axios.get(txUrl);
            const tx = response.data;
            const output = tx.vout[vout];
            if (!output) {
                throw new ISVMError(`Output ${vout} not found in transaction ${txid}`, 'UTXO_NOT_FOUND');
            }
            return {
                value: output.value * 100000000, // Convert to satoshis
                scriptPubKey: Buffer.from(output.scriptpubkey, 'hex'),
                address: output.scriptpubkey_address
            };
        }
        catch (error) {
            throw new ISVMError(`Failed to fetch UTXO details: ${error.message}`, 'UTXO_FETCH_ERROR');
        }
    }
    async fetchSpendableUtxos() {
        const networkPrefix = this.config.network === 'mainnet' ? '' : 'testnet/';
        const address = this.config.address;
        const url = `https://mempool.space/${networkPrefix}api/address/${address}/utxo`;
        try {
            const response = await axios.get(url);
            const utxos = response.data;
            // Get details for each UTXO
            const detailedUtxos = await Promise.all(utxos.map(async (utxo) => {
                const details = await this.getUtxoDetails(utxo.txid, utxo.vout);
                // Ensure the value is treated as satoshis (not converted)
                // mempool.space already returns values in satoshis
                const value = typeof utxo.value === 'string' ? parseInt(utxo.value) : utxo.value;
                // Check if value is within safe integer range
                if (!Number.isSafeInteger(value)) {
                    console.warn(`Skipping UTXO with unsafe value: ${value}`);
                    return null; // Skip this UTXO
                }
                return {
                    txid: utxo.txid,
                    vout: utxo.vout,
                    value: value, // Use the original value from mempool.space
                    scriptPubKey: details.scriptPubKey
                };
            }));
            // Filter out null values (UTXOs with unsafe values)
            const validUtxos = detailedUtxos.filter(utxo => utxo !== null);
            if (validUtxos.length === 0) {
                throw new ISVMError('No valid UTXOs available (all values too large)', 'NO_VALID_UTXOS');
            }
            return validUtxos;
        }
        catch (error) {
            throw new ISVMError(`Failed to fetch UTXOs: ${error.message}`, 'UTXO_FETCH_ERROR');
        }
    }
    /*async deploy(deployment: ContractDeployment): Promise<string> {
      const fs = await import('fs');
      if (!fs.existsSync(deployment.wasmPath)) {
        throw new ISVMError(`WASM file not found at ${deployment.wasmPath}`, 'FILE_NOT_FOUND');
      }
    
      const spinner = ora('Deploying contract...').start();
    
      try {
        // 1. Read and compress WASM file
        const wasmBytes = fs.readFileSync(deployment.wasmPath);
        const compressedWasm = await this.compressWasm(wasmBytes);
        
        // 2. Get UTXOs using mempool API
        const utxos = await this.fetchSpendableUtxos();
        if (utxos.length === 0) {
          throw new ISVMError('No UTXOs available for deployment', 'NO_UTXOS');
        }
    
        // 3. Create PSBT
        const psbt = new bitcoin.Psbt({ network: this.network });
        
        // Add inputs with proper value handling
        let totalInput = 0n; // Use BigInt for calculations
        const selectedUtxos = utxos.slice(0, 5);
        
        for (const utxo of selectedUtxos) {
          // Convert value to BigInt for safe arithmetic
          const utxoValueBigInt = BigInt(utxo.value);
          
          // Check if the individual UTXO value is within safe range for bitcoinjs-lib
          if (utxo.value > Number.MAX_SAFE_INTEGER) {
            console.warn(`Skipping UTXO ${utxo.txid}:${utxo.vout} - value too large: ${utxo.value}`);
            continue;
          }
          
          psbt.addInput({
            hash: utxo.txid,
            index: utxo.vout,
            witnessUtxo: {
              script: utxo.scriptPubKey,
              value: utxo.value // This should be the satoshi value
            }
          });
          
          totalInput += utxoValueBigInt;
        }
    
        // Check if we have any inputs
        if (psbt.inputCount === 0) {
          throw new ISVMError('No valid UTXOs could be added (all values too large)', 'NO_VALID_INPUTS');
        }
    
        // 4. Create inscription output (OP_RETURN with compressed WASM)
        const inscriptionScript = bitcoin.script.compile([
          bitcoin.opcodes.OP_RETURN,
          Buffer.concat([
            Buffer.from('application/wasm', 'utf8'),
            Buffer.from('\0', 'utf8'),
            compressedWasm
          ])
        ]);
    
        psbt.addOutput({
          script: inscriptionScript,
          value: 0
        });
    
        // 5. Create deployment metadata (matches indexer expectations)
        const deployerHash = bitcoin.crypto.hash160(
          bitcoin.address.toOutputScript(this.config.address!, this.network)
        );
        
        const deploymentData = this.createDeploymentData(deployment);
        const deploymentOpReturn = this.createOpReturn(ISVM_OPS.DEPLOY, deploymentData);
        
        psbt.addOutput({
          script: bitcoin.script.compile([
            bitcoin.opcodes.OP_RETURN,
            deploymentOpReturn
          ]),
          value: 0
        });
    
        // 6. Add change output with fee buffer
        const estimatedSize = 150 + (psbt.inputCount * 180) + compressedWasm.length;
        const fee = BigInt(estimatedSize * DEFAULT_FEE_RATE);
        const buffer = 1000n; // 1000 sats buffer
        const changeAmount = totalInput - fee - buffer;
    
        // Convert back to number for bitcoinjs-lib, but check safety first
        if (changeAmount > 546n) {
          const changeAmountNumber = Number(changeAmount);
          if (!Number.isSafeInteger(changeAmountNumber)) {
            throw new ISVMError(`Change amount too large: ${changeAmount}`, 'CHANGE_TOO_LARGE');
          }
          
          psbt.addOutput({
            address: this.config.address!,
            value: changeAmountNumber
          });
        }
    
        // 7. Sign and broadcast
        for (let i = 0; i < psbt.inputCount; i++) {
          psbt.signInput(i, this.keyPair);
        }
        psbt.finalizeAllInputs();
    
        const txHex = psbt.extractTransaction().toHex();
        const txId = await this.broadcastTransaction(txHex);
    
        spinner.succeed('Contract deployed successfully');
    
        // Return the computed contract address
        return this.computeContractAddress(
          deployerHash.toString('hex'),
          txId,
          deployment.salt
        );
      } catch (error) {
        spinner.fail('Deployment failed');
        throw error;
      }
    }*/
    // Function to generate unique filename with auto-increment
    generateUniqueFilename(contractName, networkDir, fs) {
        // Generate base filename (either from contract name or timestamp)
        const baseFilename = contractName
            ? `${contractName.toLowerCase().replace(/[^a-z0-9]/g, '-')}.json`
            : `contract-${Date.now()}.json`;
        const basePath = path.join(networkDir, baseFilename);
        // If file doesn't exist, use the base filename
        if (!fs.existsSync(basePath)) {
            return baseFilename;
        }
        // If we're using timestamp-based naming, it should be unique already
        if (!contractName) {
            return baseFilename;
        }
        // Extract name without extension for incrementing
        const nameWithoutExt = contractName.toLowerCase().replace(/[^a-z0-9]/g, '-');
        let counter = 2;
        let uniqueFilename;
        let uniquePath;
        // Keep incrementing until we find a non-existing filename
        do {
            uniqueFilename = `${nameWithoutExt}-${counter}.json`;
            uniquePath = path.join(networkDir, uniqueFilename);
            counter++;
        } while (fs.existsSync(uniquePath));
        return uniqueFilename;
    }
    async deploy(deployment) {
        const fs = await import('fs');
        if (!fs.existsSync(deployment.wasmPath)) {
            throw new ISVMError(`WASM file not found at ${deployment.wasmPath}`, 'FILE_NOT_FOUND');
        }
        const spinner = ora('Deploying contract...').start();
        try {
            // 1. Read and compress WASM file  
            spinner.text = 'Reading and compressing WASM file...';
            const wasmBytes = fs.readFileSync(deployment.wasmPath);
            const compressedWasm = await this.compressWasm(wasmBytes);
            console.log(`WASM size: ${wasmBytes.length} bytes, compressed: ${compressedWasm.length} bytes`);
            // Validate compressed size
            if (compressedWasm.length > 50000) { // 50KB limit
                throw new ISVMError('Compressed WASM too large', 'WASM_TOO_LARGE');
            }
            // 2. Get UTXOs for funding
            spinner.text = 'Fetching UTXOs...';
            const utxos = await this.fetchSpendableUtxos();
            if (utxos.length === 0) {
                throw new ISVMError('No UTXOs available for deployment', 'NO_UTXOS');
            }
            // 3. Create BTON KeyPair from existing private key
            const privkeyHex = this.keyPair.privateKey.toString('hex');
            const seckey = new KeyPair(privkeyHex);
            const pubkey = seckey.pub.rawX; // X-only pubkey for taproot
            // 4. Prepare inscription using BTON
            spinner.text = 'Preparing inscription...';
            const inscriptionParams = await this.prepareWasmInscriptionBTON(compressedWasm, deployment, seckey, pubkey);
            console.log(`Funding address: ${inscriptionParams.fundingAddress}`);
            console.log(`Inscription fee: ${inscriptionParams.fee} sats`);
            // 5. Create commit transaction using standard bitcoinjs-lib
            spinner.text = 'Creating commit transaction...';
            const commitResult = await this.createCommitTransactionHybrid(utxos, inscriptionParams, deployment);
            const commitTxId = await this.broadcastTransaction(commitResult.txHex);
            console.log(`Commit transaction broadcasted: ${commitTxId}`);
            // 6. Wait for commit to propagate - increase wait time
            spinner.text = 'Waiting for commit transaction to propagate...';
            await new Promise(resolve => setTimeout(resolve, 10000)); // Wait 10 seconds
            // 7. Verify commit transaction before creating reveal
            spinner.text = 'Verifying commit transaction...';
            try {
                await this.waitForTxConfirmation(commitTxId, 1); // Wait for at least 1 confirmation
            }
            catch (error) {
                console.warn('Could not verify commit transaction, proceeding anyway');
            }
            // 8. Create reveal transaction using BTON
            spinner.text = 'Creating reveal transaction...';
            const fundingUtxo = {
                txid: commitTxId,
                vout: commitResult.fundingOutputIndex,
                value: inscriptionParams.fundingAmount
            };
            const revealTxHex = await this.createRevealTransactionBTON(inscriptionParams, fundingUtxo);
            // Validate reveal transaction before broadcasting
            const validation = this.validateTransaction(revealTxHex);
            if (!validation.valid) {
                console.error('Reveal transaction validation failed:');
                validation.errors.forEach(error => console.error(`  - ${error}`));
                throw new ISVMError(`Invalid reveal transaction: ${validation.errors.join(', ')}`, 'INVALID_REVEAL_TX');
            }
            console.log(`Reveal transaction valid (${revealTxHex.length / 2} bytes)`);
            const revealTxId = await this.broadcastTransaction(revealTxHex);
            console.log(`Reveal transaction broadcasted: ${revealTxId}`);
            // Compute contract address BEFORE showing success message
            const deployerHash = bitcoin.crypto.hash160(bitcoin.address.toOutputScript(this.config.address, this.network));
            //const actualDeploymentData = this.createDeploymentData(deployment, commitTxId);
            //const actualOpReturn = this.createOpReturn(0x01, actualDeploymentData)
            /*const contractAddress = this.computeContractAddress(
              this.config.address!,
              commitTxId,
              deployment.salt
            );*/
            //const contractAddress = actualOpReturn.subarray(0, 20).toString('hex');
            // If actualOpReturn is the full payload including length + ISVM + type
            console.log('actualOpReturn hex:', commitResult.opreturn.toString('hex'));
            console.log('actualOpReturn bytes 7-26:', commitResult.opreturn.subarray(7, 27));
            const contractAddress = commitResult.opreturn.subarray(7, 27).toString('hex'); // Skip length(1) + ISVM(4) + type(1)
            const getContractNameFromPath = (wasmPath) => {
                // Remove directory paths and extension
                let baseName = path.basename(wasmPath, '.wasm');
                // Remove 'build/' prefix if present
                if (baseName.startsWith('build/') || baseName.startsWith('build\\')) {
                    baseName = baseName.substring(6);
                }
                // Remove any remaining path segments
                baseName = path.basename(baseName);
                // Clean up special characters
                return baseName
                    .replace(/[^a-zA-Z0-9]/g, '-') // Replace special chars with dashes
                    .replace(/-+/g, '-') // Collapse multiple dashes
                    .replace(/^-|-$/g, ''); // Remove leading/trailing dashes
            };
            const contractName = deployment.contractName || getContractNameFromPath(deployment.wasmPath) || 'UnnamedContract';
            // Get network name safely
            const networkName = this.network === bitcoin.networks.testnet ? 'testnet' :
                this.network === bitcoin.networks.regtest ? 'regtest' : 'mainnet';
            // Save deployment details to JSON file
            const deploymentInfo = {
                contractName,
                address: contractAddress,
                commitTx: commitTxId,
                revealTx: revealTxId,
                salt: deployment.salt,
                args: deployment.args || [],
                deployedAt: new Date().toISOString(),
                wasmPath: deployment.wasmPath,
                network: networkName
            };
            // Create deployments directory if it doesn't exist
            const deploymentsDir = path.join(process.cwd(), 'deployments');
            if (!fs.existsSync(deploymentsDir)) {
                fs.mkdirSync(deploymentsDir);
            }
            // Save to network-specific subdirectory
            const networkDir = path.join(deploymentsDir, networkName);
            if (!fs.existsSync(networkDir)) {
                fs.mkdirSync(networkDir);
            }
            // Generate filename (either from contract name or timestamp)
            //const filename = contractName
            //? `${contractName.toLowerCase().replace(/[^a-z0-9]/g, '-')}.json`
            //: `contract-${Date.now()}.json`;
            const filename = this.generateUniqueFilename(contractName, networkDir, fs);
            const deploymentPath = path.join(networkDir, filename);
            fs.writeFileSync(deploymentPath, JSON.stringify(deploymentInfo, null, 2));
            spinner.succeed(`Contract deployed successfully! Commit: ${commitTxId}, Reveal: ${revealTxId}`);
            console.log(`Contract address: ${contractAddress}`);
            console.log(`Deployment details saved to: ${deploymentPath}`);
            return contractAddress;
        }
        catch (error) {
            spinner.fail('Deployment failed');
            console.error('Deployment error:', error);
            // Enhanced error analysis
            if (error.message?.includes('400')) {
                console.error('\n🔍 Transaction rejected (400 error) - Common causes:');
                console.error('  • Malformed transaction structure');
                console.error('  • Invalid witness data or signatures');
                console.error('  • Insufficient fees or output below dust limit');
                console.error('  • Double-spending or invalid inputs');
                console.error('  • Script validation failure');
            }
            throw error;
        }
    }
    // Prepare WASM inscription using BTON
    async prepareWasmInscriptionBTON(compressedWasm, deployment, seckey, pubkey) {
        const ec = new TextEncoder();
        // Create the inscription script following ordinals standard
        const script = [
            pubkey,
            'OP_CHECKSIG',
            'OP_0',
            'OP_IF',
            ec.encode('ord'),
            '01', // protocol separator  
            ec.encode('application/wasm'),
            'OP_0',
            compressedWasm,
            'OP_ENDIF'
        ];
        // Encode script and create taproot tree
        const encodedScript = BTON.Script.encode(script);
        const leaf = await BTON.Tap.getLeaf(encodedScript);
        const [tapkey] = await BTON.Tap.getPubkey(pubkey, [leaf]);
        const cblock = await BTON.Tap.getPath(pubkey, leaf);
        // Create funding address (where we send funds for inscription)
        const networkPrefix = this.network.bech32 === 'tb' ? 'tb' : 'bc';
        const fundingAddress = BTON.Tap.encodeAddress(tapkey, networkPrefix);
        // Fix destination address handling
        let decodedToAddress;
        try {
            if (this.config.address.startsWith('bc1p') || this.config.address.startsWith('tb1p')) {
                // Taproot address - decode properly
                const decodedAddress = BTON.Tap.decodeAddress(this.config.address);
                decodedToAddress = "5120" + Buffer.from(decodedAddress).toString('hex');
            }
            else if (this.config.address.startsWith('bc1') || this.config.address.startsWith('tb1')) {
                // Segwit v0 address
                const outputScript = bitcoin.address.toOutputScript(this.config.address, this.network);
                decodedToAddress = outputScript.toString('hex');
            }
            else {
                // Legacy P2PKH/P2SH address
                const outputScript = bitcoin.address.toOutputScript(this.config.address, this.network);
                decodedToAddress = outputScript.toString('hex');
            }
        }
        catch (error) {
            console.error('Address decoding error:', error);
            throw new Error(`Invalid destination address: ${this.config.address}. Error: ${error.message}`);
        }
        // Calculate fees more accurately
        const baseSize = 200; // Base transaction size
        const witnessSize = 64 + encodedScript.length + 33; // sig + script + control block
        const totalSize = baseSize + Math.ceil(witnessSize / 4); // Witness discount
        const feerate = DEFAULT_FEE_RATE || 20;
        const fee = Math.ceil(feerate * totalSize / 1000) * 1000; // Round up to nearest 1000 sats
        const fundingAmount = fee + 2000; // Extra buffer
        // Create deployment metadata for OP_RETURN - use temp data for now
        const deploymentData = this.createDeploymentData(deployment);
        const deploymentOpReturn = this.createOpReturn(0x01, deploymentData); // Use 0x01 for deploy
        return {
            fundingAddress,
            decodedToAddress,
            fee,
            fundingAmount,
            encodedScript,
            script,
            leaf,
            cblock,
            seckey,
            pubkey,
            tapkey,
            data: compressedWasm,
            opReturnData: deploymentOpReturn
        };
    }
    // Create commit transaction using hybrid approach (bitcoinjs-lib for standard operations)
    async createCommitTransactionHybrid(utxos, inscriptionParams, deployment) {
        // Use bitcoinjs-lib PSBT for commit transaction (standard P2WPKH operations)
        const psbt = new bitcoin.Psbt({ network: this.network });
        // Add inputs
        let totalInput = 0;
        const selectedUtxos = utxos.slice(0, 3); // Limit to 3 UTXOs
        for (const utxo of selectedUtxos) {
            if (utxo.value > Number.MAX_SAFE_INTEGER) {
                console.warn(`Skipping UTXO ${utxo.txid}:${utxo.vout} - value too large`);
                continue;
            }
            psbt.addInput({
                hash: utxo.txid,
                index: utxo.vout,
                witnessUtxo: {
                    script: utxo.scriptPubKey,
                    value: utxo.value
                }
            });
            totalInput += utxo.value;
        }
        if (psbt.inputCount === 0) {
            throw new ISVMError('No valid UTXOs could be added', 'NO_VALID_INPUTS');
        }
        // Calculate fees and change
        const estimatedSize = 200 + (psbt.inputCount * 150);
        const commitFee = estimatedSize * (DEFAULT_FEE_RATE || 20);
        const changeAmount = totalInput - inscriptionParams.fundingAmount - commitFee;
        console.log(`Total input: ${totalInput}, Funding: ${inscriptionParams.fundingAmount}, Fee: ${commitFee}, Change: ${changeAmount}`);
        if (changeAmount < 0) {
            throw new ISVMError(`Insufficient funds. Need ${inscriptionParams.fundingAmount + commitFee} sats, have ${totalInput} sats`, 'INSUFFICIENT_FUNDS');
        }
        // 1. Funding output for inscription (to taproot address)
        psbt.addOutput({
            address: inscriptionParams.fundingAddress,
            value: inscriptionParams.fundingAmount
        });
        // 2. OP_RETURN output with deployment metadata (temp data for now)
        psbt.addOutput({
            script: inscriptionParams.opReturnData,
            value: 0
        });
        // 3. Change output (if above dust limit)
        if (changeAmount >= 546) {
            psbt.addOutput({
                address: this.config.address,
                value: changeAmount
            });
        }
        // Sign all inputs
        for (let i = 0; i < psbt.inputCount; i++) {
            psbt.signInput(i, this.keyPair);
        }
        psbt.finalizeAllInputs();
        // Get the transaction before finalizing to get the commit txid
        const commitTx = psbt.extractTransaction();
        const commitTxId = commitTx.getId();
        // Now create the final OP_RETURN with the actual commit transaction ID
        const actualDeploymentData = this.createDeploymentData(deployment, commitTxId);
        const actualOpReturn = this.createOpReturn(0x01, actualDeploymentData);
        console.log(actualOpReturn, 'actualOpReturn');
        console.log(inscriptionParams.opReturnData, 'inscriptionParams.opReturnData');
        // Update the OP_RETURN output
        commitTx.outs[1] = {
            script: actualOpReturn,
            value: 0
        };
        // We need to re-sign the transaction with the updated OP_RETURN
        // Create a new PSBT with the updated data
        const finalPsbt = new bitcoin.Psbt({ network: this.network });
        // Add inputs again
        for (const utxo of selectedUtxos) {
            if (utxo.value > Number.MAX_SAFE_INTEGER) {
                continue;
            }
            finalPsbt.addInput({
                hash: utxo.txid,
                index: utxo.vout,
                witnessUtxo: {
                    script: utxo.scriptPubKey,
                    value: utxo.value
                }
            });
        }
        // Add outputs with the correct OP_RETURN
        finalPsbt.addOutput({
            address: inscriptionParams.fundingAddress,
            value: inscriptionParams.fundingAmount
        });
        finalPsbt.addOutput({
            script: actualOpReturn,
            value: 0
        });
        if (changeAmount >= 546) {
            finalPsbt.addOutput({
                address: this.config.address,
                value: changeAmount
            });
        }
        // Sign the final transaction
        for (let i = 0; i < finalPsbt.inputCount; i++) {
            finalPsbt.signInput(i, this.keyPair);
        }
        finalPsbt.finalizeAllInputs();
        //const txHex = finalPsbt.extractTransaction().toHex();
        const finalTx = finalPsbt.extractTransaction();
        const txHex = finalTx.toHex();
        const commitTxId1 = finalTx.getId();
        return {
            txHex,
            fundingOutputIndex: 0, // Funding output is always first
            commitTxId: commitTxId1,
            opreturn: actualOpReturn
        };
    }
    // Create reveal transaction using BTON (for taproot spending)
    async createRevealTransactionBTON(params, fundingUtxo) {
        const { decodedToAddress, fee, script, leaf, cblock, seckey, tapkey } = params;
        const { txid, vout, value } = fundingUtxo;
        // Calculate output amounts
        const dustLimit = 546;
        const revealFee = fee || 1000;
        const outputValue = Math.max(dustLimit, value - revealFee);
        if (value < revealFee + dustLimit) {
            throw new Error(`Insufficient value: ${value} sats (need ${revealFee + dustLimit})`);
        }
        // Create OP_RETURN script - fixed Array.from usage
        let opReturnScript;
        if (typeof params.opReturnData === 'string') {
            // Check if it's already a complete OP_RETURN script
            if (params.opReturnData.toLowerCase().startsWith('6a')) {
                opReturnScript = params.opReturnData;
            }
            else {
                // If string, encode as UTF-8
                const encoder = new TextEncoder();
                const dataBytes = encoder.encode(params.opReturnData);
                opReturnScript = '6a' +
                    dataBytes.length.toString(16).padStart(2, '0') +
                    Buffer.from(dataBytes).toString('hex');
            }
        }
        else if (params.opReturnData instanceof Uint8Array || Buffer.isBuffer(params.opReturnData)) {
            // For bytes, check if first byte is 0x6a
            const dataBytes = Buffer.from(params.opReturnData);
            if (dataBytes[0] === 0x6a) {
                opReturnScript = dataBytes.toString('hex');
            }
            else {
                opReturnScript = '6a' +
                    dataBytes.length.toString(16).padStart(2, '0') +
                    dataBytes.toString('hex');
            }
        }
        else {
            throw new Error('OP_RETURN data must be string or bytes');
        }
        /*if (typeof params.opReturnData === 'string') {
          // If string, encode as UTF-8
          const encoder = new TextEncoder();
          const dataBytes = encoder.encode(params.opReturnData);
          opReturnScript = '6a' +
            dataBytes.length.toString(16).padStart(2, '0') +
            Buffer.from(dataBytes).toString('hex');
        } else if (params.opReturnData instanceof Uint8Array || Buffer.isBuffer(params.opReturnData)) {
          // If already bytes - use Buffer for consistent conversion
          const dataBytes = Buffer.from(params.opReturnData);
          opReturnScript = '6a' +
            dataBytes.length.toString(16).padStart(2, '0') +
            dataBytes.toString('hex');
        } else {
          throw new Error('OP_RETURN data must be string or bytes');
        }*/
        // Create transaction
        const revealTx = {
            version: 2,
            input: [{
                    txid: txid,
                    vout: vout,
                    prevout: {
                        value: value,
                        scriptPubKey: '5120' + tapkey
                    },
                    witness: []
                }],
            output: [{
                    value: outputValue,
                    scriptPubKey: decodedToAddress
                }, {
                    value: 0,
                    scriptPubKey: opReturnScript
                }],
            locktime: 0
        };
        try {
            const sec = await BTON.Tap.getSeckey(seckey.raw, [leaf]);
            const sig = await BTON.Sig.taproot.sign(seckey.raw, revealTx, 0, {
                extention: leaf // Note: Maintained spelling from working example
            });
            revealTx.input[0].witness = [sig, script, cblock];
            const rawtx = BTON.Tx.encode(revealTx);
            console.log('Reveal transaction hex:', rawtx);
            if (Buffer.from(rawtx, 'hex').length > 100000) {
                throw new Error('Transaction too large (>100KB)');
            }
            return rawtx;
        }
        catch (error) {
            console.error('Error creating reveal transaction:', error);
            throw new Error(`Failed to create reveal transaction: ${error.message}`);
        }
    }
    /*private async call(functionCall: FunctionCall): Promise<string> {
      const spinner = ora('Calling contract function...').start();
    
      try {
        // 1. Create function call data
        const functionHash = crypto.createHash('sha256')
          .update(functionCall.functionName)
          .digest()
          .slice(0, 4);
    
        const callData = this.createCallData({
          ...functionCall,
          funcHash: functionHash.toString('hex')
        });
        const callOpReturn = this.createOpReturn(ISVM_OPS.CALL, callData);
    
        // 2. Get UTXOs using mempool API
        const utxos = await this.fetchUtxos(this.config.address!);
        if (utxos.length === 0) {
          throw new ISVMError('No UTXOs available', 'NO_UTXOS');
        }
    
        // 3. Create PSBT
        const psbt = new bitcoin.Psbt({ network: this.network });
        
        // Add first UTXO as input
        const utxo = utxos[0];
        //const tx = await this.fetchTransaction(utxo.txid);
        //const scriptPubKey = tx.vout[utxo.vout].scriptPubKey.hex;
        
        psbt.addInput({
          hash: utxo.txid,
          index: utxo.vout,
          witnessUtxo: {
            script: this.getScriptPubKey(this.config.address!),
            value: utxo.value
          }
        });
    
        // 4. Add OP_RETURN output with call data
        psbt.addOutput({
          script: bitcoin.script.compile([
            bitcoin.opcodes.OP_RETURN,
            callOpReturn
          ]),
          value: 0
        });
    
        // 5. Add change output
        const estimatedSize = 150 + callOpReturn.length;
        const fee = estimatedSize * DEFAULT_FEE_RATE;
        const changeAmount = utxo.value - fee;
    
        if (changeAmount > 546) {
          psbt.addOutput({
            address: this.config.address!,
            value: changeAmount
          });
        }
    
        // 6. Sign and broadcast
        psbt.signInput(0, this.keyPair);
        psbt.finalizeAllInputs();
    
        const txHex = psbt.extractTransaction().toHex();
        return await this.broadcastTransaction(txHex);
      } catch (error) {
        spinner.fail('Function call failed');
        throw error;
      }
    }*/
    async call(functionCall) {
        // Check if we need to use callLarge for large parameter data
        const paramsJson = JSON.stringify(functionCall.params);
        const paramsBuffer = Buffer.from(paramsJson, 'utf8');
        console.log('Params JSON size:', paramsBuffer.length);
        // Conservative limit for OP_RETURN
        if (paramsBuffer.length > 40) {
            return this.callLarge(functionCall);
        }
        const spinner = ora('Calling contract function...').start();
        try {
            // 1. Create function call data
            const functionHash = crypto.createHash('sha256')
                .update(functionCall.functionName)
                .digest()
                .slice(0, 4);
            const callData = this.createCallData({
                ...functionCall,
                funcHash: functionHash.toString('hex')
            });
            const callOpReturn = this.createOpReturn(ISVM_OPS.CALL, callData);
            console.log(callOpReturn, 'callopreturn');
            // Check total OP_RETURN size
            if (callOpReturn.length > 80) {
                spinner.stop();
                return this.callLarge(functionCall);
            }
            // 2. Get UTXOs using mempool API
            const utxos = await this.fetchUtxos(this.config.address);
            if (utxos.length === 0) {
                throw new ISVMError('No UTXOs available', 'NO_UTXOS');
            }
            // 3. Create PSBT
            const psbt = new bitcoin.Psbt({ network: this.network });
            // Add first UTXO as input
            const utxo = utxos[0];
            // Simplified approach - let bitcoinjs-lib handle the script creation
            const scriptPubKey = this.getScriptPubKey(this.config.address);
            console.log(scriptPubKey, 'scriptpubkey');
            // Always use witnessUtxo for compatibility with most nodes
            psbt.addInput({
                hash: utxo.txid,
                index: utxo.vout,
                witnessUtxo: {
                    script: scriptPubKey,
                    value: utxo.value
                }
            });
            // 4. Add OP_RETURN output with call data
            psbt.addOutput({
                script: bitcoin.script.compile([
                    bitcoin.opcodes.OP_RETURN,
                    callOpReturn
                ]),
                value: 0
            });
            // 5. Add change output
            const estimatedSize = 200; // Conservative estimate
            const fee = estimatedSize * DEFAULT_FEE_RATE;
            const changeAmount = utxo.value - fee;
            if (changeAmount > 546) { // Dust threshold
                psbt.addOutput({
                    address: this.config.address,
                    value: changeAmount
                });
            }
            // 6. Sign and broadcast
            psbt.signInput(0, this.keyPair);
            psbt.finalizeAllInputs();
            const tx = psbt.extractTransaction();
            const txHex = tx.toHex();
            spinner.text = `Broadcasting transaction (${txHex.length} chars)...`;
            return await this.broadcastTransaction(txHex);
        }
        catch (error) {
            console.error('Call error:', error);
            // If ANY error occurs that might be related to size or script issues
            if (error.message?.includes('OP_RETURN_OVERFLOW') ||
                error.code === 'OP_RETURN_OVERFLOW' ||
                error.message?.includes('overflow') ||
                error.message?.includes('too large') ||
                error.message?.includes('exceed') ||
                error.message?.includes('scriptpubkey') ||
                error.message?.includes('script')) {
                spinner.stop();
                return this.callLarge(functionCall);
            }
            spinner.fail('Function call failed');
            throw error;
        }
    }
    async fetchTransaction(txid) {
        const networkPrefix = this.config.network === 'mainnet' ? '' : 'testnet/';
        const url = `https://mempool.space/${networkPrefix}api/tx/${txid}`;
        try {
            const response = await axios.get(url);
            return response.data;
        }
        catch (error) {
            throw new ISVMError(`Failed to fetch transaction: ${error.message}`, 'TX_FETCH_ERROR');
        }
    }
    async broadcastTransaction(txHex) {
        const networkPrefix = this.config.network === 'mainnet' ? '' : 'testnet/';
        // List of broadcast APIs to try (in order of preference)
        const broadcastEndpoints = [
            {
                name: 'mempool.space',
                url: `https://mempool.space/${networkPrefix}api/tx`,
                method: 'POST',
                headers: { 'Content-Type': 'text/plain' },
                data: txHex
            },
            {
                name: 'blockstream.info',
                url: `https://blockstream.info/${networkPrefix === 'testnet/' ? 'testnet/' : ''}api/tx`,
                method: 'POST',
                headers: { 'Content-Type': 'text/plain' },
                data: txHex
            },
            {
                name: 'blockcypher',
                url: `https://api.blockcypher.com/v1/btc/${this.config.network === 'mainnet' ? 'main' : 'test3'}/txs/push`,
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                data: JSON.stringify({ tx: txHex })
            }
        ];
        let lastError;
        // Validate transaction hex before broadcasting
        if (!txHex || txHex.length < 60) {
            throw new ISVMError('Invalid transaction hex - too short', 'INVALID_TX_HEX');
        }
        if (!/^[0-9a-fA-F]+$/.test(txHex)) {
            throw new ISVMError('Invalid transaction hex - contains non-hex characters', 'INVALID_TX_HEX');
        }
        console.log(`Broadcasting transaction (${txHex.length} chars)...`);
        for (const endpoint of broadcastEndpoints) {
            try {
                console.log(`Trying ${endpoint.name}...`);
                const response = await axios({
                    method: endpoint.method,
                    url: endpoint.url,
                    headers: endpoint.headers,
                    data: endpoint.data,
                    timeout: 30000 // 30 second timeout
                });
                let txid;
                // Handle different response formats
                if (typeof response.data === 'string') {
                    txid = response.data.trim();
                }
                else if (response.data.tx && response.data.tx.hash) {
                    // BlockCypher format
                    txid = response.data.tx.hash;
                }
                else if (response.data.txid) {
                    txid = response.data.txid;
                }
                else {
                    throw new Error('Unexpected response format');
                }
                // Validate txid format (64 hex characters)
                if (!/^[0-9a-fA-F]{64}$/.test(txid)) {
                    throw new Error(`Invalid txid format: ${txid}`);
                }
                console.log(`✓ Transaction broadcasted successfully via ${endpoint.name}: ${txid}`);
                return txid;
            }
            catch (error) {
                console.log(`✗ ${endpoint.name} failed:`, error.response?.data || error.message);
                lastError = error;
                // Log detailed error for debugging
                if (error.response) {
                    console.log(`Status: ${error.response.status}`);
                    console.log(`Response:`, JSON.stringify(error.response.data, null, 2));
                    // Parse common error messages
                    const errorMsg = error.response.data?.error || error.response.data?.message || error.response.data;
                    if (typeof errorMsg === 'string') {
                        if (errorMsg.includes('dust')) {
                            console.log('❌ Output below dust limit detected');
                        }
                        else if (errorMsg.includes('fee')) {
                            console.log('❌ Fee-related error detected');
                        }
                        else if (errorMsg.includes('witness')) {
                            console.log('❌ Witness data error detected');
                        }
                        else if (errorMsg.includes('script')) {
                            console.log('❌ Script validation error detected');
                        }
                    }
                }
                // Continue to next endpoint unless it's the last one
                if (endpoint === broadcastEndpoints[broadcastEndpoints.length - 1]) {
                    break;
                }
                // Wait a bit before trying next endpoint
                await new Promise(resolve => setTimeout(resolve, 1000));
            }
        }
        // All endpoints failed
        const errorDetails = lastError?.response?.data || lastError?.message || 'Unknown error';
        throw new ISVMError(`Failed to broadcast transaction via all endpoints. Last error: ${JSON.stringify(errorDetails)}`, 'BROADCAST_ERROR');
    }
    // Real implementation for transaction confirmation waiting
    async waitForTxConfirmation(txid, minConfirmations = 1) {
        const networkPrefix = this.config.network === 'mainnet' ? '' : 'testnet/';
        const maxAttempts = 60; // Wait up to 10 minutes (60 * 10 seconds)
        let attempts = 0;
        console.log(`Waiting for ${minConfirmations} confirmation(s) of ${txid}...`);
        while (attempts < maxAttempts) {
            try {
                // Try multiple APIs for getting transaction info
                const txInfo = await this.getTransactionInfo(txid);
                if (txInfo.confirmed) {
                    const confirmations = txInfo.confirmations || 0;
                    console.log(`Transaction has ${confirmations} confirmation(s)`);
                    if (confirmations >= minConfirmations) {
                        console.log(`✓ Transaction confirmed with ${confirmations} confirmations`);
                        return;
                    }
                }
                else {
                    console.log(`Transaction pending in mempool...`);
                }
            }
            catch (error) {
                console.log(`Error checking transaction status: ${error.message}`);
            }
            attempts++;
            console.log(`Waiting... (${attempts}/${maxAttempts})`);
            await new Promise(resolve => setTimeout(resolve, 10000)); // Wait 10 seconds
        }
        throw new ISVMError(`Transaction ${txid} did not achieve ${minConfirmations} confirmations within timeout`, 'CONFIRMATION_TIMEOUT');
    }
    // Get transaction information from multiple APIs
    async getTransactionInfo(txid) {
        const networkPrefix = this.config.network === 'mainnet' ? '' : 'testnet/';
        const endpoints = [
            {
                name: 'mempool.space',
                url: `https://mempool.space/${networkPrefix}api/tx/${txid}`,
                parser: (data) => ({
                    confirmed: data.status?.confirmed || false,
                    confirmations: data.status?.confirmed ? (data.status.block_height ? 1 : 0) : 0,
                    blockHeight: data.status?.block_height,
                    blockHash: data.status?.block_hash
                })
            },
            {
                name: 'blockstream.info',
                url: `https://blockstream.info/${networkPrefix === 'testnet/' ? 'testnet/' : ''}api/tx/${txid}`,
                parser: (data) => ({
                    confirmed: !!data.status?.confirmed,
                    confirmations: data.status?.confirmed ? 1 : 0,
                    blockHeight: data.status?.block_height,
                    blockHash: data.status?.block_hash
                })
            },
            {
                name: 'blockcypher',
                url: `https://api.blockcypher.com/v1/btc/${this.config.network === 'mainnet' ? 'main' : 'test3'}/txs/${txid}`,
                parser: (data) => ({
                    confirmed: data.confirmations > 0,
                    confirmations: data.confirmations || 0,
                    blockHeight: data.block_height,
                    blockHash: data.block_hash
                })
            }
        ];
        for (const endpoint of endpoints) {
            try {
                const response = await axios.get(endpoint.url, { timeout: 15000 });
                return endpoint.parser(response.data);
            }
            catch (error) {
                console.log(`${endpoint.name} failed to get tx info:`, error.message);
                continue;
            }
        }
        throw new Error('Failed to get transaction information from all APIs');
    }
    // Optional: Check if transaction is in mempool
    async isTransactionInMempool(txid) {
        const networkPrefix = this.config.network === 'mainnet' ? '' : 'testnet/';
        try {
            const response = await axios.get(`https://mempool.space/${networkPrefix}api/tx/${txid}`, { timeout: 10000 });
            // If we get the transaction data, check if it's confirmed
            return !response.data.status?.confirmed;
        }
        catch (error) {
            if (error.response?.status === 404) {
                return false; // Transaction not found
            }
            throw error;
        }
    }
    // Enhanced transaction validation before broadcasting
    validateTransaction(txHex) {
        const errors = [];
        // Basic hex validation
        if (!txHex || typeof txHex !== 'string') {
            errors.push('Transaction hex is empty or invalid type');
            return { valid: false, errors };
        }
        if (txHex.length < 60) {
            errors.push('Transaction hex too short (minimum ~30 bytes)');
        }
        if (!/^[0-9a-fA-F]+$/.test(txHex)) {
            errors.push('Transaction hex contains invalid characters');
        }
        if (txHex.length % 2 !== 0) {
            errors.push('Transaction hex has odd length');
        }
        // Size validation (max 400KB)
        const txSizeBytes = txHex.length / 2;
        if (txSizeBytes > 400000) {
            errors.push(`Transaction too large: ${txSizeBytes} bytes (max 400KB)`);
        }
        // Basic structure validation
        try {
            const txBuffer = Buffer.from(txHex, 'hex');
            // Check version (first 4 bytes)
            if (txBuffer.length < 4) {
                errors.push('Transaction too short to contain version');
            }
            else {
                const version = txBuffer.readUInt32LE(0);
                if (version < 1 || version > 2) {
                    errors.push(`Invalid transaction version: ${version}`);
                }
            }
        }
        catch (error) {
            errors.push(`Failed to parse transaction hex: ${error.message}`);
        }
        return {
            valid: errors.length === 0,
            errors
        };
    }
    async getContract(address) {
        const spinner = ora('Fetching contract information...').start();
        try {
            const contract = await this.indexerCall(`/contract/${address}`);
            spinner.succeed('Contract information retrieved');
            const table = new Table({
                head: ['Property', 'Value'],
                colWidths: [20, 60]
            });
            table.push(['Address', contract.address], ['Deployer', contract.deployer], ['Inscription ID', contract.inscriptionId], ['Type', contract.contractType], ['Version', contract.version.toString()], ['Last Updated', contract.lastUpdated.toString()], ['Is Paused', contract.isPaused ? 'Yes' : 'No']);
            console.log(table.toString());
            return contract;
        }
        catch (error) {
            spinner.fail('Failed to fetch contract');
            throw error;
        }
    }
    async getState(address) {
        const spinner = ora('Fetching contract state...').start();
        try {
            const state = await this.indexerCall(`/contract/${address}/state`);
            spinner.succeed('Contract state retrieved');
            console.log(chalk.cyan('Contract State:'));
            console.log(JSON.stringify(state, null, 2));
            return state;
        }
        catch (error) {
            spinner.fail('Failed to fetch contract state');
            throw error;
        }
    }
    async getEvents(address, options = {}) {
        const spinner = ora('Fetching contract events...').start();
        try {
            const events = await this.indexerCall(`/contract/${address}/events`, { params: options });
            spinner.succeed(`Retrieved ${events.length} events`);
            if (events.length > 0) {
                const table = new Table({
                    head: ['Block', 'Event', 'Data', 'Tx Hash'],
                    colWidths: [10, 15, 40, 20]
                });
                events.slice(0, 10).forEach((event) => {
                    table.push([
                        event.blockHeight,
                        event.event,
                        JSON.stringify(event.data).slice(0, 37) + '...',
                        event.txHash.slice(0, 16) + '...'
                    ]);
                });
                console.log(table.toString());
            }
            return events;
        }
        catch (error) {
            spinner.fail('Failed to fetch events');
            throw error;
        }
    }
    async simulate(address, functionName, params) {
        const spinner = ora('Simulating function call...').start();
        try {
            const result = await axios.post(`${this.config.indexerUrl}/contract/${address}/simulate`, {
                function: functionName,
                params,
                caller: this.config.address
            });
            spinner.succeed('Simulation completed');
            console.log(chalk.cyan('Simulation Result:'));
            console.log(`Success: ${result.data.success ? chalk.green('✓') : chalk.red('✗')}`);
            console.log(`Gas Used: ${result.data.gasUsed}`);
            if (result.data.returnValue !== undefined) {
                console.log(`Return Value: ${JSON.stringify(result.data.returnValue)}`);
            }
            if (result.data.error) {
                console.log(chalk.red(`Error: ${result.data.error}`));
            }
            if (result.data.events && result.data.events.length > 0) {
                console.log(chalk.yellow('Events:'));
                result.data.events.forEach((event, i) => {
                    console.log(`  ${i + 1}. ${event.event}: ${JSON.stringify(event.data)}`);
                });
            }
            return result.data;
        }
        catch (error) {
            spinner.fail('Simulation failed');
            throw error;
        }
    }
    /*async watch(address: string): Promise<void> {
      console.log(chalk.cyan(`Watching contract ${address} for events...`));
      console.log(chalk.gray('Press Ctrl+C to stop'));
  
      try {
          let wsUrl = this.config.indexerUrl;
        if (wsUrl.startsWith('http://')) {
            wsUrl = 'ws://' + wsUrl.slice(7);
        } else if (wsUrl.startsWith('https://')) {
            wsUrl = 'wss://' + wsUrl.slice(8);
        }
        const ws = new WebSocket(`${wsUrl}/events`);
        //const ws = new WebSocket(`${this.config.indexerUrl.replace('http', 'ws')}/events`);
  
        ws.on('open', () => {
          ws.send(JSON.stringify({ type: 'subscribe', contract: address }));
          console.log(chalk.green('Connected to event stream'));
        });
  
        ws.on('message', (data) => {
          const event = JSON.parse(data.toString());
          if (event.contract === address) {
            const timestamp = new Date().toLocaleTimeString();
            console.log(chalk.yellow(`[${timestamp}] ${event.event}:`), JSON.stringify(event.data));
          }
        });
  
        ws.on('error', (error) => {
          console.error(chalk.red('WebSocket error:'), error.message);
        });
  
        ws.on('close', () => {
          console.log(chalk.gray('Connection closed'));
        });
  
      } catch (error) {
        throw new ISVMError(`Failed to watch contract: ${error.message}`, 'WATCH_ERROR');
      }
    }*/
    async watch(address) {
        console.log(chalk.cyan(`Watching contract ${address} for events...`));
        console.log(chalk.gray('Press Ctrl+C to stop'));
        try {
            let wsUrl = this.config.indexerUrl;
            if (wsUrl.startsWith('http://')) {
                wsUrl = 'ws://' + wsUrl.slice(7);
            }
            else if (wsUrl.startsWith('https://')) {
                wsUrl = 'wss://' + wsUrl.slice(8);
            }
            const ws = new WebSocket(`${wsUrl}/events`);
            return new Promise((resolve, reject) => {
                ws.on('open', () => {
                    ws.send(JSON.stringify({ type: 'subscribe', contract: address }));
                    console.log(chalk.green('Connected to event stream'));
                    resolve(ws);
                });
                ws.on('message', (data) => {
                    const event = JSON.parse(data.toString());
                    if (event.contract === address) {
                        const timestamp = new Date().toLocaleTimeString();
                        console.log(chalk.yellow(`[${timestamp}] ${event.event}:`), JSON.stringify(event.data));
                    }
                });
                ws.on('error', (error) => {
                    console.error(chalk.red('WebSocket error:'), error.message);
                    reject(error);
                });
                ws.on('close', () => {
                    console.log(chalk.gray('Connection closed'));
                });
            });
        }
        catch (error) {
            throw new ISVMError(`Failed to watch contract: ${error.message}`, 'WATCH_ERROR');
        }
    }
    async listContracts(options = {}) {
        const spinner = ora('Fetching contracts...').start();
        try {
            const contracts = await this.indexerCall('/contracts', { params: options });
            spinner.succeed(`Found ${contracts.length} contracts`);
            if (contracts.length > 0) {
                const table = new Table({
                    head: ['Address', 'Deployer', 'Type', 'Version', 'Status'],
                    colWidths: [25, 25, 15, 10, 10]
                });
                contracts.slice(0, 20).forEach((contract) => {
                    table.push([
                        contract.address.slice(0, 20) + '...',
                        contract.deployer.slice(0, 20) + '...',
                        contract.contractType || 'Unknown',
                        contract.version.toString(),
                        contract.isPaused ? 'Paused' : 'Active'
                    ]);
                });
                console.log(table.toString());
            }
            return contracts;
        }
        catch (error) {
            spinner.fail('Failed to fetch contracts');
            throw error;
        }
    }
    /*async compileContract(sourcePath: string, outputPath: string): Promise<void> {
      const spinner = ora('Compiling contract...').start();
      try {
        const { exec } = require('child_process');
        await new Promise((resolve, reject) => {
          exec(`asc ${sourcePath} -o ${outputPath} --optimize`,
            (error: Error, stdout: string, stderr: string) => {
              if (error) {
                spinner.fail('Compilation failed');
                reject(new ISVMError('COMPILATION_FAILED', stderr));
                return;
              }
              spinner.succeed('Contract compiled successfully');
              resolve(stdout);
            }
          );
        });
      } catch (error) {
        throw new ISVMError('COMPILATION_ERROR', error.message);
      }
    }*/
    async compileContract(sourcePath, outputPath) {
        const spinner = ora('Compiling contract...').start();
        try {
            // Replace require with dynamic imports
            const { exec } = await import('child_process');
            const fs = await import('fs');
            const path = await import('path');
            // Check if source file exists
            if (!fs.existsSync(sourcePath)) {
                spinner.fail('Source file not found');
                throw new ISVMError('FILE_NOT_FOUND', `Source file ${sourcePath} does not exist`);
            }
            // Create output directory if it doesn't exist
            const outputDir = path.dirname(outputPath);
            if (!fs.existsSync(outputDir)) {
                fs.mkdirSync(outputDir, { recursive: true });
            }
            // Enhanced command with flags to fix WASM section errors
            const command = `asc ${sourcePath} -o ${outputPath} --runtime minimal --optimize --noAssert --importMemory --memoryBase 0`;
            console.log('Running command:', command);
            console.log('Current working directory:', process.cwd());
            await new Promise((resolve, reject) => {
                exec(command, {
                    cwd: process.cwd(),
                    env: process.env,
                    maxBuffer: 1024 * 1024 * 10, // Increased to 10MB buffer
                    timeout: 60000 // 60 second timeout
                }, (error, stdout, stderr) => {
                    // Always log output for debugging
                    if (stdout)
                        console.log('STDOUT:', stdout);
                    if (stderr)
                        console.log('STDERR:', stderr);
                    if (error) {
                        spinner.fail('Compilation failed');
                        console.error('ERROR:', error.message);
                        console.error('Error code:', error.code || 'Unknown');
                        console.error('Signal:', error.signal || 'None');
                        reject(new ISVMError('COMPILATION_FAILED', `${error.message}\n${stderr}`));
                        return;
                    }
                    // Check if output file was actually created
                    if (!fs.existsSync(outputPath)) {
                        spinner.fail('Output file not created');
                        reject(new ISVMError('COMPILATION_FAILED', 'Output file was not created'));
                        return;
                    }
                    // Basic WASM validation (check magic number)
                    try {
                        const buffer = fs.readFileSync(outputPath);
                        const magicNumber = buffer.slice(0, 4);
                        const expectedMagic = Buffer.from([0x00, 0x61, 0x73, 0x6d]); // "\0asm"
                        if (!magicNumber.equals(expectedMagic)) {
                            spinner.fail('Invalid WASM output');
                            reject(new ISVMError('INVALID_WASM', 'Output file is not a valid WebAssembly module'));
                            return;
                        }
                        console.log('✅ WASM validation passed - File size:', buffer.length, 'bytes');
                    }
                    catch (validationError) {
                        spinner.fail('Output validation failed');
                        reject(new ISVMError('VALIDATION_FAILED', `Could not validate output: ${validationError.message}`));
                        return;
                    }
                    spinner.succeed('Contract compiled successfully');
                    resolve(stdout);
                });
            });
        }
        catch (error) {
            spinner.fail('Compilation error');
            throw error;
        }
    }
    parseParams(paramsStr) {
        try {
            // Handle bigint notation (123n)
            const json = paramsStr.replace(/([0-9]+)n/g, '"$1n"')
                .replace(/"0x([0-9a-fA-F]+)"/g, '"hex:$1"');
            const parsed = JSON.parse(json);
            // Convert special notations
            const processValue = (value) => {
                if (typeof value === 'string') {
                    if (value.endsWith('n')) {
                        return BigInt(value.slice(0, -1));
                    }
                    if (value.startsWith('hex:')) {
                        return Buffer.from(value.slice(4), 'hex');
                    }
                }
                return value;
            };
            return Array.isArray(parsed)
                ? parsed.map(processValue)
                : [processValue(parsed)];
        }
        catch (error) {
            throw new ISVMError('PARAM_PARSE_ERROR', `Failed to parse parameters: ${error.message}`);
        }
    }
    async deployWithDependencies(deployment, dependencies) {
        const spinner = ora('Resolving dependencies...').start();
        try {
            // Verify all dependencies exist
            for (const dep of dependencies) {
                if (!this.isValidContractAddress(dep.address)) {
                    throw new ISVMError(`Invalid contract address: ${dep.address}`, 'INVALID_ADDRESS');
                }
                spinner.text = `Checking dependency: ${dep.address}`;
                if (!await this.getContract(dep.address)) {
                    throw new ISVMError('DEPENDENCY_NOT_FOUND', `Dependency contract not found: ${dep.address}`);
                }
            }
            // Include dependency interfaces in constructor args
            const enhancedArgs = [
                ...deployment.constructorArgs,
                { __dependencies: dependencies }
            ];
            const enhancedDeployment = {
                ...deployment,
                constructorArgs: enhancedArgs
            };
            spinner.text = 'Deploying contract with dependencies...';
            return await this.deploy(enhancedDeployment);
        }
        catch (error) {
            spinner.fail('Deployment with dependencies failed');
            throw error;
        }
    }
    createBatchCallData(calls) {
        const MAX_BATCH_CALLS = 10;
        const MAX_TOTAL_SIZE = 800; // Leaves room for other transaction parts
        const MAX_PARAMS_SIZE = 255; // Fits in 1 byte length
        if (calls.length > MAX_BATCH_CALLS) {
            throw new ISVMError(`Maximum ${MAX_BATCH_CALLS} calls per batch allowed`, 'BATCH_LIMIT_EXCEEDED');
        }
        const buffers = [];
        let totalSize = 0;
        for (const call of calls) {
            // Validate contract address
            if (!this.isValidContractAddress(call.contractAddress)) {
                throw new ISVMError(`Invalid contract address: ${call.contractAddress}`, 'INVALID_ADDRESS');
            }
            // Compute function hash
            const functionHash = crypto.createHash('sha256')
                .update(call.functionName)
                .digest()
                .slice(0, 4);
            // Serialize parameters
            const paramsBuffer = Buffer.from(JSON.stringify(call.params), 'utf8');
            if (paramsBuffer.length > MAX_PARAMS_SIZE) {
                throw new ISVMError(`Parameters too large for call ${call.functionName} (max ${MAX_PARAMS_SIZE} bytes)`, 'PARAMS_TOO_LARGE');
            }
            // Create call buffer
            const callBuffer = Buffer.concat([
                Buffer.from(call.contractAddress, 'hex'), // 20 bytes
                functionHash, // 4 bytes
                Buffer.from([paramsBuffer.length]), // 1 byte length
                paramsBuffer // variable length
            ]);
            // Check total size
            totalSize += callBuffer.length;
            if (totalSize > MAX_TOTAL_SIZE) {
                throw new ISVMError(`Batch call data too large (max ${MAX_TOTAL_SIZE} bytes)`, 'BATCH_TOO_LARGE');
            }
            buffers.push(callBuffer);
        }
        return Buffer.concat(buffers);
    }
    async executeBatch(calls) {
        if (!this.keyPair) {
            throw new ISVMError('Private key not configured', 'NO_PRIVATE_KEY');
        }
        const spinner = ora('Preparing batch transaction...').start();
        try {
            // 1. Create batch call data
            const batchData = this.createBatchCallData(calls);
            const batchOpReturn = this.createOpReturn(0x03, batchData); // OP_BATCH = 0x03
            // 2. Get UTXOs
            const utxos = await this.rpcCall('listunspent', [1, 9999999, [this.config.address]]);
            if (utxos.length === 0) {
                throw new ISVMError('No UTXOs available', 'NO_UTXOS');
            }
            // 3. Create PSBT
            const psbt = new bitcoin.Psbt({ network: this.network });
            let totalInput = 0;
            // Add inputs (use up to 3 UTXOs to avoid large transactions)
            for (const utxo of utxos.slice(0, 3)) {
                psbt.addInput({
                    hash: utxo.txid,
                    index: utxo.vout,
                    witnessUtxo: {
                        script: Buffer.from(utxo.scriptPubKey, 'hex'),
                        value: Math.floor(utxo.amount * 100000000)
                    }
                });
                totalInput += Math.floor(utxo.amount * 100000000);
            }
            // Add batch output
            psbt.addOutput({
                script: bitcoin.script.compile([
                    bitcoin.opcodes.OP_RETURN,
                    batchOpReturn
                ]),
                value: 0
            });
            // 4. Estimate fee and add change
            const feeRate = await this.rpcCall('estimatesmartfee', [1]);
            const satPerByte = feeRate.feerate ? Math.ceil(feeRate.feerate * 100000) : 20;
            // Calculate transaction size (approximate)
            const txSize = 100 + (psbt.inputCount * 150) + batchOpReturn.length;
            const fee = txSize * satPerByte;
            const changeAmount = totalInput - fee;
            if (changeAmount > 546) { // Dust limit
                psbt.addOutput({
                    address: this.config.address,
                    value: changeAmount
                });
            }
            else if (totalInput - fee < 0) {
                throw new ISVMError('Insufficient funds for batch call', 'INSUFFICIENT_FUNDS');
            }
            // 5. Sign and broadcast
            spinner.text = 'Signing transaction...';
            for (let i = 0; i < psbt.inputCount; i++) {
                psbt.signInput(i, this.keyPair);
            }
            psbt.finalizeAllInputs();
            spinner.text = 'Broadcasting transaction...';
            const txHex = psbt.extractTransaction().toHex();
            const txId = await this.rpcCall('sendrawtransaction', [txHex]);
            spinner.succeed('Batch call submitted successfully!');
            console.log(chalk.green(`Transaction ID: ${txId}`));
            return txId;
        }
        catch (error) {
            spinner.fail('Batch call failed');
            throw error;
        }
    }
    async configure() {
        const questions = [
            {
                type: 'list',
                name: 'network',
                message: 'Select network:',
                choices: ['mainnet', 'testnet', 'regtest'],
                default: this.config.network
            },
            {
                type: 'input',
                name: 'rpcUrl',
                message: 'Bitcoin RPC URL:',
                default: this.config.rpcUrl
            },
            {
                type: 'input',
                name: 'rpcUser',
                message: 'Bitcoin RPC username:',
                default: this.config.rpcUser
            },
            {
                type: 'password',
                name: 'rpcPassword',
                message: 'Bitcoin RPC password:',
                default: this.config.rpcPassword
            },
            {
                type: 'input',
                name: 'indexerUrl',
                message: 'ISVM Indexer URL:',
                default: this.config.indexerUrl
            },
            {
                type: 'input',
                name: 'privateKey',
                message: 'Private key (WIF format):',
                default: this.config.privateKey
            }
        ];
        const answers = await inquirer.prompt(questions);
        // Derive address from private key
        if (answers.privateKey) {
            try {
                const keyPair = ECPair.fromWIF(answers.privateKey, this.getNetwork());
                const { address } = bitcoin.payments.p2wpkh({
                    pubkey: keyPair.publicKey,
                    network: this.getNetwork()
                });
                answers.address = address;
            }
            catch (error) {
                throw new ISVMError('Invalid private key format', 'INVALID_PRIVATE_KEY');
            }
        }
        this.config = { ...this.config, ...answers };
        // Save configuration
        const configPath = path.join(process.cwd(), 'isvm.config.json');
        fs.writeFileSync(configPath, JSON.stringify(this.config, null, 2));
        console.log(chalk.green('Configuration saved successfully!'));
        if (answers.address) {
            console.log(chalk.cyan(`Your address: ${answers.address}`));
        }
    }
}
// CLI Setup
const program = new Command();
const cli = new ISVMCLI();
program
    .name('isvm')
    .description('ISVM Protocol CLI - Deploy and interact with Bitcoin smart contracts')
    .version('1.0.0');
program
    .command('config')
    .description('Configure ISVM CLI settings')
    .action(async () => {
    try {
        await cli.configure();
    }
    catch (error) {
        console.error(chalk.red('Configuration failed:'), error.message);
        process.exit(1);
    }
});
program
    .command('compile')
    .description('Compile an AssemblyScript contract to WASM')
    .requiredOption('-s, --source <path>', 'Path to AssemblyScript source file')
    .option('-o, --output <path>', 'Output WASM file path', 'contract.wasm')
    .action(async (options) => {
    try {
        await cli.compileContract(options.source, options.output);
    }
    catch (error) {
        console.error(chalk.red('Compilation failed:'), error.message);
        process.exit(1);
    }
});
program
    .command('deploy')
    .description('Deploy a WASM contract')
    .requiredOption('-f, --file <path>', 'Path to WASM file')
    .option('-a, --args <args>', 'Constructor arguments (JSON)', '[]')
    .option('-s, --salt <salt>', 'Salt for contract address generation', '0')
    .option('--flags <flags>', 'Contract flags (number)', '0')
    .option('--timelock <timelock>', 'Timelock period (blocks)')
    .option('--compile', 'Compile source to WASM before deployment', false)
    .action(async (options) => {
    try {
        let wasmPath = options.file;
        if (options.compile || options.file.endsWith('.ts')) {
            const outputPath = options.file.replace('.ts', '.wasm');
            await cli.compileContract(options.file, outputPath);
            wasmPath = outputPath;
        }
        const deployment = {
            wasmPath: wasmPath,
            constructorArgs: JSON.parse(options.args),
            salt: options.salt,
            flags: parseInt(options.flags),
            timelock: options.timelock ? parseInt(options.timelock) : undefined
        };
        await cli.deploy(deployment);
    }
    catch (error) {
        console.error(chalk.red('Deployment failed:'), error.message);
        process.exit(1);
    }
});
program
    .command('call')
    .description('Call a contract function')
    .requiredOption('-c, --contract <address>', 'Contract address')
    .requiredOption('-f, --function <name>', 'Function name')
    .option('-p, --params <params>', 'Function parameters (JSON)', '[]')
    .option('-g, --gas <limit>', 'Gas limit')
    .action(async (options) => {
    try {
        const functionCall = {
            contractAddress: options.contract,
            functionName: options.function,
            //params: JSON.parse(options.params),
            params: cli.parseParams(options.params),
            gasLimit: options.gas ? parseInt(options.gas) : undefined
        };
        await cli.call(functionCall);
    }
    catch (error) {
        console.error(chalk.red('Function call failed:'), error.message);
        process.exit(1);
    }
});
program
    .command('get')
    .description('Get contract information')
    .argument('<address>', 'Contract address')
    .action(async (address) => {
    try {
        await cli.getContract(address);
    }
    catch (error) {
        console.error(chalk.red('Failed to get contract:'), error.message);
        process.exit(1);
    }
});
program
    .command('state')
    .description('Get contract state')
    .argument('<address>', 'Contract address')
    .action(async (address) => {
    try {
        await cli.getState(address);
    }
    catch (error) {
        console.error(chalk.red('Failed to get state:'), error.message);
        process.exit(1);
    }
});
program
    .command('events')
    .description('Get contract events')
    .argument('<address>', 'Contract address')
    .option('--from <block>', 'From block height')
    .option('--to <block>', 'To block height')
    .option('--limit <limit>', 'Limit number of results', '100')
    .action(async (address, options) => {
    try {
        const queryOptions = {};
        if (options.from)
            queryOptions.from_block = options.from;
        if (options.to)
            queryOptions.to_block = options.to;
        if (options.limit)
            queryOptions.limit = options.limit;
        await cli.getEvents(address, queryOptions);
    }
    catch (error) {
        console.error(chalk.red('Failed to get events:'), error.message);
        process.exit(1);
    }
});
program
    .command('simulate')
    .description('Simulate a function call')
    .requiredOption('-c, --contract <address>', 'Contract address')
    .requiredOption('-f, --function <name>', 'Function name')
    .option('-p, --params <params>', 'Function parameters (JSON)', '[]')
    .action(async (options) => {
    try {
        await cli.simulate(options.contract, options.function, JSON.parse(options.params));
    }
    catch (error) {
        console.error(chalk.red('Simulation failed:'), error.message);
        process.exit(1);
    }
});
program
    .command('watch')
    .description('Watch contract events in real-time')
    .argument('<address>', 'Contract address')
    .action(async (address) => {
    try {
        // Store the WebSocket instance returned by watch()
        const ws = await cli.watch(address);
        // Cleanup handler
        const cleanup = () => {
            if (ws) {
                ws.close();
                console.log(chalk.yellow('\nWebSocket connection closed'));
            }
            process.exit(0);
        };
        // Handle CTRL+C
        process.on('SIGINT', cleanup);
        // Handle process termination
        process.on('exit', cleanup);
    }
    catch (error) {
        console.error(chalk.red('Watch failed:'), error.message);
        process.exit(1);
    }
});
program
    .command('list')
    .description('List all contracts')
    .option('--limit <limit>', 'Limit number of results', '20')
    .option('--offset <offset>', 'Offset for pagination', '0')
    .action(async (options) => {
    try {
        await cli.listContracts(options);
    }
    catch (error) {
        console.error(chalk.red('Failed to list contracts:'), error.message);
        process.exit(1);
    }
});
program
    .command('template')
    .description('Generate contract templates')
    .argument('<type>', 'Template type (isvm20, multisig, amm, etc.)')
    .option('-o, --output <path>', 'Output file path', 'contracts/example.ts')
    .action(async (type, options) => {
    try {
        const templates = {
            isvm20: `// Refactored ISVM Token Contract using persistent storage APIs

// Import memory from env
declare const memory: WebAssembly.Memory;

// Host storage access
@external("isvm_standard_libs_as", "__native_get_storage")
declare function __native_get_storage(keyPtr: usize, keyLen: usize): usize;
@external("isvm_standard_libs_as", "__native_set_storage")
declare function __native_set_storage(keyPtr: usize, keyLen: usize, valuePtr: usize, valueLen: usize): void;
@external("isvm_standard_libs_as", "__native_delete_storage")
declare function __native_delete_storage(keyPtr: usize, keyLen: usize): void;
@external("isvm_standard_libs_as", "__native_has_storage")
declare function __native_has_storage(keyPtr: usize, keyLen: usize): i32;

@external("isvm_standard_libs_as", "__native_revert")
declare function __native_revert(messagePtr: usize, messageLen: usize): void;
@external("isvm_standard_libs_as", "__native_caller_id")
declare function __native_caller_id(): i32;
@external("isvm_standard_libs_as", "__native_deployer_id")
declare function __native_deployer_id(): i32;
@external("isvm_standard_libs_as", "__resolve_string_to_id")
declare function __resolve_string_to_id(strPtr: usize, strLen: usize): i32;
@external("isvm_standard_libs_as", "__resolve_id_to_string")
declare function __resolve_id_to_string(id: i32, outputPtr: usize, maxLen: usize): i32;
@external("isvm_standard_libs_as", "__resolve_address_to_id")
declare function __resolve_address_to_id(ptr: usize, len: usize): i32;
@external("isvm_standard_libs_as", "__get_address_id")
declare function __get_address_id(ptr: usize, len: usize): i32;
@external("isvm_standard_libs_as", "__getString")
declare function __getString(ptr: usize): string;

function revert(msg: string): void {
  __native_revert(changetype<usize>(msg), msg.length);
}

function storeU64(key: string, value: u64): void {
  console.log(\`DEBUG: storeU64 called with key: "\${key}" (length: \${key.length}), value: \${value}\`);
  
  const keyPtr = changetype<usize>(key);
  const valueStr = value.toString();
  const valuePtr = changetype<usize>(valueStr);
  
  console.log(\`DEBUG: About to call __native_set_storage with keyPtr: \${keyPtr}, keyLen: \${key.length}, valuePtr: \${valuePtr}, valueLen: \${valueStr.length}\`);
  
  __native_set_storage(keyPtr, key.length, valuePtr, valueStr.length);
}

function loadU64(key: string): u64 {
  console.log(\`DEBUG: loadU64 called with key: "\${key}" (length: \${key.length})\`);
  
  // Get the key as a proper string pointer for the native call
  const keyPtr = changetype<usize>(key);
  console.log(\`DEBUG: About to call __native_get_storage with keyPtr: \${keyPtr}, keyLen: \${key.length}\`);
  
  // Call the native storage function - this returns a pointer to the VALUE string
  const valuePtr = __native_get_storage(keyPtr, key.length);
  if (valuePtr === 0) {
    console.log(\`DEBUG: loadU64 returning 0 for key: "\${key}" (no value found)\`);
    return 0;
  }
  
  console.log(\`DEBUG: loadU64 received value pointer: \${valuePtr}\`);
  
  // Read the string directly from memory using AssemblyScript string structure
  // AssemblyScript strings have this structure:
  // [ptr-8]: reference count (i32)
  // [ptr-4]: string length in UTF-16 code units (i32)  
  // [ptr]:   UTF-16 string data
  
  const stringLength = load<i32>(valuePtr - 4);
  console.log(\`DEBUG: String length from memory: \${stringLength}\`);
  
  // Build the string by reading UTF-16 code units
  let result = "";
  for (let i = 0; i < stringLength; i++) {
    const codeUnit = load<u16>(valuePtr + i * 2);
    result += String.fromCharCode(codeUnit);
  }
  
  console.log(\`DEBUG: loadU64 decoded string: "\${result}" for key: "\${key}"\`);
  
  // Parse the string to u64
  const parsed = U64.parseInt(result);
  console.log(\`DEBUG: loadU64 parsed value: \${parsed} for key: "\${key}"\`);
  
  return parsed;
}

function storeI32(key: string, value: i32): void {
  storeU64(key, value as u64);
}

function loadI32(key: string): i32 {
  return loadU64(key) as i32;
}

// Key Constants
const KEY_NAME = "token_name";
const KEY_SYMBOL = "token_symbol";
const KEY_TOTAL_SUPPLY = "total_supply";
const KEY_DECIMALS = "decimals";
const KEY_DEPLOYER_ID = "deployer_id";

// Helpers
function balanceKey(id: i32): string {
  return "balance:" + id.toString();
}
function allowanceKey(owner: i32, spender: i32): string {
  return "allowance:" + owner.toString() + ":" + spender.toString();
}

// State Getters
function getBalance(id: i32): u64 {
  return loadU64(balanceKey(id));
}
function setBalance(id: i32, amt: u64): void {
  storeU64(balanceKey(id), amt);
}
function getAllowance(owner: i32, spender: i32): u64 {
  return loadU64(allowanceKey(owner, spender));
}
function setAllowance(owner: i32, spender: i32, amt: u64): void {
  storeU64(allowanceKey(owner, spender), amt);
}

// Helper function to resolve ID to string
function resolveIdToString(id: i32): string {
    const maxLength = 256;
    console.log(\`🚀 Starting resolveIdToString with id: \${id}\`);
    
    // Allocate memory for the output
    const outputPtr = __alloc(maxLength);
    console.log(\`📦 Allocated memory at ptr: \${outputPtr}\`);
    
    // Call the resolver - this returns the actual length of the string
    const actualLength = __resolve_id_to_string(id, outputPtr, maxLength);
    console.log(\`📊 Raw actualLength returned: \${actualLength}\`);
    console.log(\`📊 actualLength as i32: \${<i32>actualLength}\`);
    console.log(\`📊 actualLength as usize: \${<usize>actualLength}\`);
    
    // Check what's actually in memory regardless of the return value
    console.log(\`🔍 Memory contents after call:\`);
    for (let j: usize = 0; j < 20; j++) {
        const byte = load<u8>(outputPtr + j);
        console.log(\`  Byte \${j}: \${byte} (char: '\${String.fromCharCode(byte)}')\`);
        if (byte === 0) break; // Stop at null terminator
    }
    
    // Try reading with a fixed length first (we know it should be 7)
    console.log(\`🧪 Testing with fixed length 7:\`);
    let testResult = "";
    for (let i: usize = 0; i < 7; i++) {
        const char = String.fromCharCode(load<u8>(outputPtr + i));
        testResult += char;
        console.log(\`  Char \${i}: '\${char}'\`);
    }
    console.log(\`🧪 Test result: "\${testResult}"\`);
    
    if (actualLength === 0) {
        console.log(\`❌ actualLength is 0, returning empty string\`);
        __free(outputPtr);
        return "";
    }
    
    // Now try with the actual length
    let result = "";
    const safeLength = actualLength > 0 && actualLength < 1000 ? <usize>actualLength : 7;
    console.log(\`📝 Using safe length: \${safeLength}\`);
    
    for (let i: usize = 0; i < safeLength; i++) {
        result += String.fromCharCode(load<u8>(outputPtr + i));
    }
    
    console.log(\`📝 Final result: "\${result}"\`);
    __free(outputPtr);
    return result;
}

// Main API
export function constructor(nameId: i32, symbolId: i32, supply: u64, decimals: u8): i32 {
  if (loadI32(KEY_NAME) !== 0) revert("Already initialized");
  if (supply == 0 || decimals > 8) revert("Invalid params");

  storeI32(KEY_NAME, nameId);
  storeI32(KEY_SYMBOL, symbolId);
  storeU64(KEY_TOTAL_SUPPLY, supply);
  storeI32(KEY_DECIMALS, decimals);
  const deployer = __native_deployer_id();
  storeI32(KEY_DEPLOYER_ID, deployer);
  setBalance(deployer, supply);
  return 1;
}

export function balance_of(id: i32): u64 {
  return getBalance(id);
}

export function transfer(toId: i32, amount: u64): i32 {
  const from = __native_caller_id();
  const bal = getBalance(from);
  if (bal < amount) revert("Insufficient");
  setBalance(from, bal - amount);
  setBalance(toId, getBalance(toId) + amount);
  return 1;
}

export function approve(spender: i32, amt: u64): i32 {
  const owner = __native_caller_id();
  setAllowance(owner, spender, amt);
  return 1;
}

export function transfer_from(from: i32, to: i32, amt: u64): i32 {
  const caller = __native_caller_id();
  const allowance = getAllowance(from, caller);
  if (allowance < amt) revert("Allowance low");
  const bal = getBalance(from);
  if (bal < amt) revert("Balance low");
  setAllowance(from, caller, allowance - amt);
  setBalance(from, bal - amt);
  setBalance(to, getBalance(to) + amt);
  return 1;
}

export function mint(to: i32, amt: u64): i32 {
  const caller = __native_caller_id();
  const deployer = loadI32(KEY_DEPLOYER_ID);
  if (caller != deployer) revert("Not deployer");
  const supply = loadU64(KEY_TOTAL_SUPPLY);
  const newSupply = supply + amt;
  storeU64(KEY_TOTAL_SUPPLY, newSupply);
  setBalance(to, getBalance(to) + amt);
  return 1;
}

export function burn(amt: u64): i32 {
  const caller = __native_caller_id();
  const bal = getBalance(caller);
  if (bal < amt) revert("Insufficient");
  setBalance(caller, bal - amt);
  storeU64(KEY_TOTAL_SUPPLY, loadU64(KEY_TOTAL_SUPPLY) - amt);
  return 1;
}

export function get_name(): string {
  const id = loadI32(KEY_NAME);
  return resolveIdToString(id);
}
export function get_symbol(): string {
  const id = loadI32(KEY_SYMBOL);
  return resolveIdToString(id);
}
export function get_decimals(): u8 {
  return loadI32(KEY_DECIMALS) as u8;
}
export function get_total_supply(): u64 {
  return loadU64(KEY_TOTAL_SUPPLY);
}
export function debug_keys(): void {
  console.log(\`KEY_NAME: "\${KEY_NAME}" (length: \${KEY_NAME.length})\`);
  console.log(\`KEY_SYMBOL: "\${KEY_SYMBOL}" (length: \${KEY_SYMBOL.length})\`);
  console.log(\`KEY_TOTAL_SUPPLY: "\${KEY_TOTAL_SUPPLY}" (length: \${KEY_TOTAL_SUPPLY.length})\`);
  console.log(\`KEY_DECIMALS: "\${KEY_DECIMALS}" (length: \${KEY_DECIMALS.length})\`);
  console.log(\`KEY_DEPLOYER_ID: "\${KEY_DEPLOYER_ID}" (length: \${KEY_DEPLOYER_ID.length})\`);
}

// Test the balance key function
export function debug_balance_key(id: i32): void {
  const key = balanceKey(id);
  console.log(\`balanceKey(\${id}) = "\${key}" (length: \${key.length})\`);
}`,
            //multisig: `import { MultiSig } from 'isvm_standard_libs_as';\n\nexport class MyMultiSig extends MultiSig {\n  constructor(owners: string[], threshold: i32) {\n    super(owners, threshold);\n  }\n}`,
            // Add more templates as needed
        };
        if (!templates[type]) {
            throw new ISVMError('TEMPLATE_NOT_FOUND', `Unknown template type: ${type}`);
        }
        fs.writeFileSync(options.output, templates[type]);
        console.log(chalk.green(`Template generated at ${options.output}`));
    }
    catch (error) {
        console.error(chalk.red('Template generation failed:'), error.message);
        process.exit(1);
    }
});
program
    .command('deploy-with-deps')
    .description('Deploy a contract with dependencies')
    .requiredOption('-f, --file <path>', 'Path to WASM file')
    .option('-s, --salt <salt>', 'Salt for contract address generation', '0')
    .option('--flags <flags>', 'Contract flags (number)', '0')
    .requiredOption('-d, --deps <json>', 'Dependencies JSON array')
    // ... other deployment options
    .action(async (options) => {
    try {
        const dependencies = JSON.parse(options.deps);
        const deployment = {
            wasmPath: options.file,
            constructorArgs: JSON.parse(options.args || '[]'),
            salt: options.salt,
            flags: parseInt(options.flags),
            // ... other deployment options
        };
        await cli.deployWithDependencies(deployment, dependencies);
    }
    catch (error) {
        console.error(chalk.red('Deployment failed:'), error.message);
        process.exit(1);
    }
});
program
    .command('test')
    .description('Run tests against a deployed contract')
    .requiredOption('-c, --contract <address>', 'Contract address to test')
    .option('-t, --tests <path>', 'Path to test file', './tests.json')
    .action(async (options) => {
    try {
        // Read and parse test file with type assertion
        const testData = JSON.parse(fs.readFileSync(options.tests, 'utf8'));
        const results = [];
        for (const test of testData.tests) {
            const spinner = ora(`Running test: ${test.name}`).start();
            try {
                const result = await cli.simulate(options.contract, test.function, test.params);
                if (result.success) {
                    if (test.expected && JSON.stringify(result.returnValue) !== JSON.stringify(test.expected)) {
                        spinner.fail(`Test failed: ${test.name}`);
                        results.push({
                            name: test.name,
                            status: 'failed',
                            error: `Expected ${JSON.stringify(test.expected)}, got ${JSON.stringify(result.returnValue)}`
                        });
                    }
                    else {
                        spinner.succeed(`Test passed: ${test.name}`);
                        results.push({
                            name: test.name,
                            status: 'passed'
                        });
                    }
                }
                else {
                    spinner.fail(`Test failed: ${test.name}`);
                    results.push({
                        name: test.name,
                        status: 'failed',
                        error: result.error
                    });
                }
            }
            catch (error) {
                spinner.fail(`Test error: ${test.name}`);
                results.push({
                    name: test.name,
                    status: 'error',
                    error: error instanceof Error ? error.message : 'Unknown error'
                });
            }
        }
        // Print test summary
        const passed = results.filter(r => r.status === 'passed').length;
        const failed = results.filter(r => r.status === 'failed').length;
        const errors = results.filter(r => r.status === 'error').length;
        console.log(chalk.bold('\nTest Summary:'));
        console.log(chalk.green(`✓ ${passed} passed`));
        console.log(chalk.red(`✗ ${failed} failed`));
        console.log(chalk.yellow(`⚠ ${errors} errors`));
        // Print detailed failures
        const failures = results.filter(r => r.status !== 'passed');
        if (failures.length > 0) {
            console.log(chalk.bold('\nFailed Tests:'));
            failures.forEach(test => {
                console.log(chalk.red(`- ${test.name}`));
                if (test.error) {
                    console.log(`  Reason: ${test.error}`);
                }
            });
        }
    }
    catch (error) {
        console.error(chalk.red('Testing failed:'), error instanceof Error ? error.message : 'Unknown error');
        process.exit(1);
    }
});
program
    .command('batch')
    .description('Execute multiple function calls in one transaction')
    .requiredOption('-c, --calls <json>', 'JSON array of function calls', JSON.parse)
    .option('--examples', 'Show batch call examples', false)
    .action(async (options) => {
    if (options.examples) {
        console.log(chalk.cyan('\nBatch Call Examples:'));
        console.log(`
        Simple batch:
        [
          {
            "contractAddress": "a1b2c3...",
            "functionName": "transfer",
            "params": ["0x1234...", 100]
          },
          {
            "contractAddress": "d4e5f6...",
            "functionName": "approve",
            "params": ["0x5678...", 200]
          }
        ]

        Complex batch:
        [
          {
            "contractAddress": "contract1...",
            "functionName": "multiStepOperation",
            "params": [1, "test", true]
          },
          {
            "contractAddress": "contract2...",
            "functionName": "updateState",
            "params": [{"key": "value"}]
          }
        ]
      `);
        return;
    }
    try {
        if (!Array.isArray(options.calls)) {
            throw new ISVMError('Calls must be an array', 'INVALID_CALLS_FORMAT');
        }
        // Validate each call
        const validatedCalls = options.calls.map((call) => {
            if (!call.contractAddress || !call.functionName) {
                throw new ISVMError('Each call must have contractAddress and functionName', 'INVALID_CALL_FORMAT');
            }
            return {
                contractAddress: call.contractAddress,
                functionName: call.functionName,
                params: call.params || []
            };
        });
        await cli.executeBatch(validatedCalls);
    }
    catch (error) {
        console.error(chalk.red('Batch call failed:'), error.message);
        console.log(chalk.yellow('Use --examples to see usage examples'));
        process.exit(1);
    }
});
program
    .command('pause')
    .description('Pause a smart contract')
    .argument('<address>', 'Contract address to pause')
    .option('--check', 'Verify contract is paused after transaction', false)
    .action(async (address, options) => {
    try {
        const txId = await cli.pauseContract(address, true);
        if (options.check) {
            const spinner = ora('Verifying contract state...').start();
            try {
                // Wait a few seconds for indexer to process
                await new Promise(resolve => setTimeout(resolve, 5000));
                const contract = await cli.indexerCall(`/contract/${address}`);
                if (contract.isPaused) {
                    spinner.succeed('Contract successfully paused');
                }
                else {
                    spinner.fail('Contract pause verification failed');
                    console.log(chalk.yellow('Transaction was sent but contract state may not have updated yet'));
                }
            }
            catch (error) {
                spinner.fail('Verification failed');
                console.log(chalk.yellow(`Transaction was sent (${txId}) but verification failed: ${error.message}`));
            }
        }
    }
    catch (error) {
        console.error(chalk.red('Pause failed:'), error.message);
        process.exit(1);
    }
});
program
    .command('unpause')
    .description('Unpause a smart contract')
    .argument('<address>', 'Contract address to unpause')
    .option('--check', 'Verify contract is unpaused after transaction', false)
    .action(async (address, options) => {
    try {
        const txId = await cli.pauseContract(address, false);
        if (options.check) {
            const spinner = ora('Verifying contract state...').start();
            try {
                // Wait a few seconds for indexer to process
                await new Promise(resolve => setTimeout(resolve, 5000));
                const contract = await cli.indexerCall(`/contract/${address}`);
                if (!contract.isPaused) {
                    spinner.succeed('Contract successfully unpaused');
                }
                else {
                    spinner.fail('Contract unpause verification failed');
                    console.log(chalk.yellow('Transaction was sent but contract state may not have updated yet'));
                }
            }
            catch (error) {
                spinner.fail('Verification failed');
                console.log(chalk.yellow(`Transaction was sent (${txId}) but verification failed: ${error.message}`));
            }
        }
    }
    catch (error) {
        console.error(chalk.red('Unpause failed:'), error.message);
        process.exit(1);
    }
});
// Error handling
process.on('unhandledRejection', (error) => {
    console.error(chalk.red('Unhandled error:'), error);
    process.exit(1);
});
process.on('SIGINT', () => {
    console.log(chalk.yellow('\nGracefully shutting down...'));
    process.exit(0);
});
// Parse and execute
program.parse();
//# sourceMappingURL=isvm_cli.js.map