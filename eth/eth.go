package main

import (
	"context"
	"crypto/ecdsa"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/meshplus/hyperbench-common/base"
	"os"
	"path"
	"reflect"
	"strings"
	"sync"

	"math/big"
	"math/rand"
	"time"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	fcom "github.com/meshplus/hyperbench-common/common"
	"github.com/spf13/cast"
	"github.com/spf13/viper"
)

const gasLimit = 300000
const sep = "\n"

// Contract contains the abi and bin files of contract
type Contract struct {
	Name            string
	ABI             string
	BIN             string
	parsedAbi       abi.ABI
	contractAddress []common.Address
}
type option struct {
	gas    *big.Int
	setGas bool
	noSend bool
}

// ETH the client of eth
type ETH struct {
	*base.BlockchainBase
	ethClient   *ethclient.Client
	privateKey  *ecdsa.PrivateKey
	publicKey   *ecdsa.PublicKey
	auth        *bind.TransactOpts
	startBlock  uint64
	endBlock    uint64
	chainID     *big.Int
	gasPrice    *big.Int
	round       uint64
	nonce       uint64
	engineCap   uint64
	workerNum   uint64
	contractNum uint64
	wkIdx       uint64
	vmIdx       uint64
	accCount    uint64
	op          option
}

// Msg contains message of context
type Msg struct {
	Contract *Contract
}

var (
	lock            sync.RWMutex
	accounts        map[string]*ecdsa.PrivateKey
	accountAddrList []string
	PrivateK        *ecdsa.PrivateKey
	fromAddress     common.Address
	contracts       map[string]Contract
)

func init() {
	log := fcom.GetLogger("eth")
	configPath := viper.GetString(fcom.ClientConfigPath)
	options := viper.GetStringMap(fcom.ClientOptionPath)
	files, err := os.ReadDir(configPath + "/keystore")
	if err != nil {
		log.Errorf("access keystore failed:%v", err)
	}

	lock.Lock()

	accounts = make(map[string]*ecdsa.PrivateKey)
	for i, file := range files {
		fileName := file.Name()
		accountAddrList, accounts, err = KeystoreToPrivateKey(configPath+"/keystore/"+fileName, cast.ToString(options["keypassword"]))
		if err != nil {
			log.Errorf("access account file failed: %v", err)
			return
		}

		if i == 0 {
			addr := accountAddrList[0]
			PrivateK = accounts[addr]

			fromAddress = common.HexToAddress(addr)
		}
	}

	lock.Unlock()
}

// New use given blockchainBase create ETH.
func New(blockchainBase *base.BlockchainBase) (client interface{}, err error) {
	lock.Lock()
	defer lock.Unlock()

	log := fcom.GetLogger("eth")
	ethConfig, err := os.Open(blockchainBase.ConfigPath + "/eth.toml")
	if err != nil {
		log.Errorf("load eth configuration fialed: %v", err)
		return nil, err
	}
	viper.MergeConfig(ethConfig)
	ethClient, err := ethclient.Dial(viper.GetString("rpc.node") + ":" + viper.GetString("rpc.port"))
	if err != nil {
		log.Errorf("ethClient initiate fialed: %v", err)
		return nil, err
	}

	nonce, err := ethClient.PendingNonceAt(context.Background(), fromAddress)
	if err != nil {
		log.Errorf("pending nonce failed: %v", err)
		return nil, err
	}

	gasPrice, err := ethClient.SuggestGasPrice(context.Background())
	if err != nil {
		log.Errorf("generate gasprice failed: %v", err)
		return nil, err
	}
	chainID, err := ethClient.NetworkID(context.Background())
	if err != nil {
		log.Errorf("get chainID failed: %v", err)
		return nil, err
	}
	auth, err := bind.NewKeyedTransactorWithChainID(PrivateK, chainID)
	if err != nil {
		log.Errorf("generate transaction options failed: %v", err)
		return nil, err
	}
	auth.Nonce = big.NewInt(int64(nonce))
	auth.Value = big.NewInt(0)       // in wei
	auth.GasLimit = uint64(gasLimit) // in units
	auth.GasPrice = gasPrice
	startBlock, err := ethClient.HeaderByNumber(context.Background(), nil)
	if err != nil {
		log.Errorf("get number of headerblock failed: %v", err)
		return nil, err
	}
	workerNum := uint64(len(viper.GetStringSlice(fcom.EngineURLsPath)))
	if workerNum == 0 {
		workerNum = 1
	}
	contractNum := viper.GetUint64(fcom.ClientContractNum)
	if contractNum == 0 {
		contractNum = 1
	}
	vmIdx := uint64(blockchainBase.Options["vmIdx"].(int64))
	wkIdx := uint64(blockchainBase.Options["wkIdx"].(int64))
	accCount := uint64(blockchainBase.Options["accounts"].(int64))

	if accCount > uint64(len(accountAddrList)) {
		return nil, fmt.Errorf("actual account count %d is bigger than importing account count: %d", accCount, len(accountAddrList))
	}

	client = &ETH{
		BlockchainBase: blockchainBase,
		ethClient:      ethClient,
		privateKey:     PrivateK,
		auth:           auth,
		chainID:        chainID,
		gasPrice:       gasPrice,
		startBlock:     startBlock.Number.Uint64(),
		round:          0,
		nonce:          nonce,
		engineCap:      viper.GetUint64(fcom.EngineCapPath),
		workerNum:      workerNum,
		contractNum:    contractNum,
		vmIdx:          vmIdx,
		wkIdx:          wkIdx,
		accCount:       accCount,
		op: option{
			setGas: false,
			noSend: false,
		},
	}
	return
}
func (e *ETH) DeployContract() error {
	lock.Lock()
	defer lock.Unlock()

	if e.BlockchainBase.ContractPath != "" {
		var er error
		contracts, er = newContract(e.BlockchainBase.ContractPath)
		if er != nil {
			e.Logger.Errorf("initiate contract failed: %v", er)
			return er
		}
	} else {
		return nil
	}

	for name, contract := range contracts {
		parsed, err := abi.JSON(strings.NewReader(contract.ABI))
		if err != nil {
			e.Logger.Errorf("decode abi of contract failed: %v", err)
			return err
		}
		contract.parsedAbi = parsed

		// deploy contract num is contractNum for every contract
		for i := 0; i < int(e.contractNum); i++ {
			e.auth.GasPrice = nil
			e.auth.GasLimit = 0

			contractAddress, _, _, err := bind.DeployContract(e.auth, parsed, common.FromHex(contract.BIN), e.ethClient, e.Args...)
			if err != nil {
				e.Logger.Errorf("deploycontract failed: %v", err)
				continue
			}

			contract.contractAddress = append(contract.contractAddress, contractAddress)

			e.nonce++
			e.auth.Nonce = big.NewInt(int64(e.nonce))
		}
		// update contract
		contracts[name] = contract
		e.Logger.Infof("deploy contract: %s success, count: %d", name, len(contract.contractAddress))
	}

	return nil
}

// Invoke invoke contract with funcName and args in eth network
func (e *ETH) Invoke(invoke fcom.Invoke, ops ...fcom.Option) *fcom.Result {
	lock.RLock()
	defer lock.RUnlock()

	contract, ok := contracts[invoke.Contract]
	if !ok {
		e.Logger.Errorf("invoke error, no this contract: %s", invoke.Contract)
		return e.handleErr()
	}

	// invoke random contract address by the contract
	index := rand.Intn(len(contract.contractAddress))
	contractAddress := contract.contractAddress[index]

	instance := bind.NewBoundContract(contractAddress, contract.parsedAbi, e.ethClient, e.ethClient, e.ethClient)
	// nonce := e.nonce + (e.wkIdx+e.round*e.workerNum)*(e.engineCap/e.workerNum) + e.vmIdx + 1
	// e.round++
	// e.auth.Nonce = big.NewInt(int64(nonce))
	from := common.HexToAddress(invoke.Caller)
	nonce, err := e.ethClient.PendingNonceAt(context.Background(), from)
	if err != nil {
		e.Logger.Errorf("invoke: pending nonce failed: %v", err)
		return e.handleErr()
	}

	gasPrice, err := e.ethClient.SuggestGasPrice(context.Background())
	if err != nil {
		e.Logger.Errorf("generate gasprice failed: %v", err)
		return e.handleErr()
	}

	priKey := accounts[invoke.Caller]
	auth, err := bind.NewKeyedTransactorWithChainID(priKey, e.chainID)
	if err != nil {
		e.Logger.Errorf("generate transaction options failed: %v", err)
		return e.handleErr()
	}
	auth.Nonce = big.NewInt(int64(nonce))
	auth.Value = big.NewInt(0)       // in wei
	auth.GasLimit = uint64(gasLimit) // in units
	auth.GasPrice = gasPrice

	if e.op.setGas {
		auth.GasPrice = e.op.gas
	}
	auth.NoSend = e.op.noSend
	buildTime := time.Now().UnixNano()
	tx, err := instance.Transact(auth, invoke.Func, invoke.Args...)
	sendTime := time.Now().UnixNano()
	if err != nil {
		e.Logger.Errorf("invoke error: %v", err)
		return &fcom.Result{
			Label:     invoke.Func,
			UID:       fcom.InvalidUID,
			Ret:       []interface{}{},
			Status:    fcom.Failure,
			BuildTime: buildTime,
			SendTime:  sendTime,
		}
	}
	ret := &fcom.Result{
		Label:     invoke.Func,
		UID:       tx.Hash().String(),
		Ret:       []interface{}{tx.Data()},
		Status:    fcom.Success,
		BuildTime: buildTime,
		SendTime:  sendTime,
	}

	return ret

}

// Confirm check the result of `Invoke` or `Transfer`
func (e *ETH) Confirm(result *fcom.Result, ops ...fcom.Option) *fcom.Result {
	if result.UID == "" ||
		result.UID == fcom.InvalidUID ||
		result.Status != fcom.Success ||
		result.Label == fcom.InvalidLabel {
		return result
	}
	tx, _, err := e.ethClient.TransactionByHash(context.Background(), common.HexToHash(result.UID))
	result.ConfirmTime = time.Now().UnixNano()
	if err != nil || tx == nil {
		e.Logger.Errorf("query failed: %v", err)
		result.Status = fcom.Unknown
		return result
	}
	result.Status = fcom.Confirm
	return result
}

// Transfer transfer a amount of money from a account to the other one
func (e *ETH) Transfer(args fcom.Transfer, ops ...fcom.Option) (result *fcom.Result) {
	lock.RLock()
	defer lock.RUnlock()

	// nonce := e.nonce + (e.wkIdx+e.round*e.workerNum)*(e.engineCap/e.workerNum) + e.vmIdx
	// e.round++
	from := common.HexToAddress(args.From)
	nonce, err := e.ethClient.PendingNonceAt(context.Background(), from)
	if err != nil {
		e.Logger.Errorf("transfer: pending nonce failed: %v", err)
		return e.handleErr()
	}

	value := big.NewInt(args.Amount)

	toAddress := common.HexToAddress(args.To)
	data := []byte(args.Extra)
	if e.op.setGas {
		e.gasPrice = e.op.gas
	}
	tx := types.NewTransaction(nonce, toAddress, value, gasLimit, e.gasPrice, data)
	buildTime := time.Now().UnixNano()

	account, ok := accounts[args.From]
	if !ok {
		e.Logger.Errorf("get account error: from: %s", args.From)
		return e.handleErr()
	}
	signedTx, err := types.SignTx(tx, types.NewEIP155Signer(e.chainID), account)
	if err != nil {
		return &fcom.Result{
			Label:     fcom.BuiltinTransferLabel,
			UID:       fcom.InvalidUID,
			Ret:       []interface{}{},
			Status:    fcom.Failure,
			BuildTime: buildTime,
		}
	}

	err = e.ethClient.SendTransaction(context.Background(), signedTx)
	sendTime := time.Now().UnixNano()
	if err != nil {
		e.Logger.Errorf("transfer error: %v", err)
		return &fcom.Result{
			Label:     fcom.BuiltinTransferLabel,
			UID:       fcom.InvalidUID,
			Ret:       []interface{}{},
			Status:    fcom.Failure,
			BuildTime: buildTime,
			SendTime:  sendTime,
		}
	}

	ret := &fcom.Result{
		Label:     fcom.BuiltinTransferLabel,
		UID:       signedTx.Hash().String(),
		Ret:       []interface{}{tx.Data()},
		Status:    fcom.Success,
		BuildTime: buildTime,
		SendTime:  sendTime,
	}
	//e.Logger.Infof("transfer result: %+v", ret)

	return ret
}

// SetContext set test group context in go client
func (e *ETH) SetContext(context string) error {
	e.Logger.Debugf("prepare msg: %v", context)
	msg := &Msg{}

	if context == "" {
		e.Logger.Infof("Prepare nothing")
		return nil
	}

	err := json.Unmarshal([]byte(context), msg)
	if err != nil {
		e.Logger.Errorf("can not unmarshal msg: %v \n err: %v", context, err)
		return err
	}

	// set contractaddress,abi,publickey
	// e.contract = msg.Contract
	// if e.contract != nil {
	// 	parsed, err := abi.JSON(strings.NewReader(e.contract.ABI))
	// 	if err != nil {
	// 		e.Logger.Errorf("decode abi of contract failed: %v", err)
	// 		return err
	// 	}
	// 	e.contract.parsedAbi = parsed
	// }
	// publicKey := e.privateKey.Public()
	// publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
	// if !ok {
	// 	e.Logger.Error("cannot assert type: publicKey is not of type *ecdsa.PublicKey")
	// 	return errors.New("cannot assert type: publicKey is not of type *ecdsa.PublicKey")
	// }
	// e.publicKey = publicKeyECDSA
	return nil
}

// ResetContext reset test group context in go client
func (e *ETH) ResetContext() error {
	return nil
}

// GetContext generate TxContext
func (e *ETH) GetContext() (string, error) {

	// msg := &Msg{
	// 	Contract: e.contract,
	// }

	// bytes, err := json.Marshal(msg)

	// return string(bytes), err
	return "", nil
}

// Statistic statistic remote node performance
func (e *ETH) Statistic(statistic fcom.Statistic) (*fcom.RemoteStatistic, error) {

	from, to := statistic.From, statistic.To

	statisticData, err := GetTPS(e, from, to)
	if err != nil {
		e.Logger.Errorf("getTPS failed: %v", err)
		return nil, err
	}
	return statisticData, nil
}

// LogStatus records blockheight and time
func (e *ETH) LogStatus() (end int64, err error) {
	blockInfo, err := e.ethClient.HeaderByNumber(context.Background(), nil)
	if err != nil {
		return 0, err
	}
	e.endBlock = blockInfo.Number.Uint64()
	end = time.Now().UnixNano()
	return end, err
}

// GetRandomAccount get random account except addr
func (e *ETH) GetRandomAccount(addr string) string {
	lock.RLock()
	defer lock.RUnlock()

	accountAddr := strings.TrimPrefix(addr, "0x")
	randomNumber := rand.Int63n(int64(e.accCount))

	account := accountAddrList[randomNumber]
	if account == accountAddr {
		index := (randomNumber + 1) % int64(e.accCount)
		return accountAddrList[index]
	}
	return account
}

// GetRandomAccountByGroup get random account by group
func (e *ETH) GetRandomAccountByGroup() string {
	lock.RLock()
	defer lock.RUnlock()

	// total group
	totalGroup := e.workerNum * e.engineCap
	// my group
	group := e.wkIdx*e.engineCap + e.vmIdx

	accountNumOneGroup := e.accCount / totalGroup

	randomNumber := rand.Int63n(int64(accountNumOneGroup))
	accIndex := randomNumber + int64(group*accountNumOneGroup)

	return accountAddrList[accIndex]
}

// Option ethereum receive options to change the config to client.
// Supported Options:
//  1. key: gas
//     valueType: int
//     effect: set gas will set gasprice used for transaction
//     not set gas will let client use gas which initiate when client created
//     default: default setGas is false, gas is what initiate when client created
//  2. key: nosend
//     valueType: bool
//     effect: set nosend true will let client do not send transaction to node when invoking contract
//     set nosend false will let client send transaction to node when invoking contract
//     default: default nosend is false, gas is what initiate when client created
func (e *ETH) Option(options fcom.Option) error {
	for key, value := range options {
		switch key {
		case "gas":
			if gas, ok := value.(float64); ok {
				e.op.setGas = true
				e.op.gas = big.NewInt(int64(gas))
			} else {
				return errors.New("option `gas` type error: " + reflect.TypeOf(value).Name())
			}
		case "nosend":
			if nosend, ok := value.(bool); ok {
				e.op.noSend = nosend
			} else {
				return errors.New("option `nosend` type error: " + reflect.TypeOf(value).Name())
			}
		}
	}
	return nil
}

func (e *ETH) GetContractAddrByName(contractName string) string {
	contract, exists := contracts[contractName]
	if !exists {
		return ""
	}

	if len(contract.contractAddress) == 0 {
		return ""
	}

	return contract.contractAddress[0].String()
}

func (e *ETH) handleErr() *fcom.Result {
	return &fcom.Result{
		UID:    fcom.InvalidUID,
		Ret:    []interface{}{},
		Status: fcom.Failure,
	}
}

func KeystoreToPrivateKey(privateKeyFile, password string) ([]string, map[string]*ecdsa.PrivateKey, error) {
	log := fcom.GetLogger("eth")
	keyjson, err := os.ReadFile(privateKeyFile)
	if err != nil {
		log.Errorf("read keyjson file failed: %v", err)
		return nil, nil, err
	}

	// TODO: use password to decrypt

	dstAddrList := make([]string, 0)
	dstKeyMap := make(map[string]*ecdsa.PrivateKey)
	keys := strings.Split(string(keyjson), sep)
	for _, key := range keys {
		sk, err := crypto.HexToECDSA(strings.TrimPrefix(key, "0x"))
		if err != nil {
			return nil, nil, err
		}

		addr := crypto.PubkeyToAddress(sk.PublicKey)
		dstAddr := strings.TrimPrefix(addr.String(), "0x")
		dstAddrList = append(dstAddrList, dstAddr)
		dstKeyMap[dstAddr] = sk
	}

	return dstAddrList, dstKeyMap, nil
}

// GetTPS calculates txnum and blocknum of pressure test
func GetTPS(e *ETH, beginTime, endTime int64) (*fcom.RemoteStatistic, error) {
	blockCounter, txCounter := 0, 0

	for i := e.startBlock; i < e.endBlock; i++ {
		block, err := e.ethClient.BlockByNumber(context.Background(), new(big.Int).SetUint64(i))
		if err != nil {
			return nil, err
		}
		txCounter += len(block.Transactions())
		blockCounter++
	}

	statistic := &fcom.RemoteStatistic{
		Start:    beginTime,
		End:      endTime,
		BlockNum: blockCounter,
		TxNum:    txCounter,
		CTps:     float64(txCounter) * 1e9 / float64(endTime-beginTime),
		Bps:      float64(blockCounter) * 1e9 / float64(endTime-beginTime),
	}
	return statistic, nil
}

// newContract initiates abi and bin files of contract
func newContract(contractPath string) (contracts map[string]Contract, err error) {
	files, err := os.ReadDir(contractPath)
	abiDataMap := make(map[string][]byte)
	binDataMap := make(map[string][]byte)
	if err != nil {
		return nil, err
	}
	for _, file := range files {
		fileExt := path.Ext(file.Name())
		name := strings.TrimSuffix(file.Name(), fileExt)
		if fileExt == ".abi" {
			abiData, err := os.ReadFile(contractPath + "/" + file.Name())
			if err != nil {
				return nil, err
			}
			abiDataMap[name] = abiData
		}
		if fileExt == ".bin" {
			binData, err := os.ReadFile(contractPath + "/" + file.Name())
			if err != nil {
				return nil, err
			}
			binDataMap[name] = binData
		}
	}

	dstContract := make(map[string]Contract)
	for name, abiData := range abiDataMap {
		binData, ok := binDataMap[name]
		if !ok {
			return nil, fmt.Errorf("no bin data for file: %s", name)
		}
		dstContract[name] = Contract{
			Name: name,
			BIN:  string(binData),
			ABI:  string(abiData),
		}
	}

	return dstContract, nil
}
