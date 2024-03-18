package main

import (
	"Veder/core"
	crypto "Veder/lib/crypto"
	"fmt"
	_ "github.com/go-sql-driver/mysql"
	"github.com/jmoiron/sqlx"

	"log"
	"strings"
	"time"
	"unsafe"
)

/*
	func main() {
		m := M.NewMerkleSquare(4)
		m.Append([]byte("key1"), []byte("value1"), []byte("signature1"))
		m.Append([]byte("key2"), []byte("value2"), []byte("signature2"))
		m.Append([]byte("key3"), []byte("value3"), []byte("signature3"))
		m.Append([]byte("key3"), []byte("value3.2"), []byte("signature3"))
		// proof := m.GenerateExistenceProof([]byte("key3"), 2, 0, 3)
		// nodehash := M.ComputeLeafNodeHash([]byte("key3"), []byte("value3"), []byte("signature3"), 2)
		// oldHashes := m.GenerateKeyHash([]byte("key2"))
		// res, _, _ := M.VerifyExistenceProof(m.GetDigest(), nodehash, []byte("key2"), 2, 0, proof, oldHashes)

		// proof := m.ProveLatest([]byte("key3"), []byte("value3.2"), 3, 4)
		// res := M.VerifyPKProof(m.GetDigest(), []byte("key3"), []byte("value3.2"), []byte("signature3"), 3, proof)
		// print(res)

		exclude := []uint32{}
		keyHashes := m.GenerateKeyHash([]byte("key3"), exclude...)
		proof, _ := m.GenerateBatchedLookupProof(0, 4, []byte("key3"), []uint32{2, 3})
		res, _ := M.VerifyBatchedLookupProof(0, []byte("key3"), keyHashes, m.GetDigest(), proof)
		print(res)
	}
*/
func main() {
	//TestIndexProcess()
	//TestIndex()
	//TestIndexVerify()
	//TestIndexInit()
	//
	//TestIndexVerifyBandwidth()

	TestIndexConstruction()
	TestIndexVerifyTimeSpaceAll()
}

var nodes []*core.MerkleSquare
var MS = make(map[int]*core.MerkleSquare)
var keywordExistence = make(map[int]map[string][]uint32)
var key0 []byte = []byte("TestKey0")
var key1 []byte = []byte("TestKey1")

/*
 * 测试单次索引更新各阶段消耗时间
 * 包括索引初始化，密钥更新，密钥验证
 */

func TestIndexProcess() {
	kw := "apple"

	time0 := time.Now()
	MS[0] = core.NewMerkleSquare(19)
	time1 := time.Now()

	kwHashStr := string(crypto.Hash([]byte(kw)))
	lastChar := []byte{kwHashStr[len(kwHashStr)-1]}
	tempProof, _ := crypto.Encrypt(lastChar, key0)
	crypto.Hash(tempProof, tempProof)

	time4 := time.Now()

	MS[0].Append([]byte("key1"), []byte("value1"), []byte("signature1"))
	time5 := time.Now()

	initTime := time1.Sub(time0)
	indexUpdateTime := time5.Sub(time4)

	fmt.Printf("Index init %s, and update: %s \n", initTime, indexUpdateTime)
}

func TestIndex() {
	totalTime := time.Duration(0)

	time0 := time.Now()

	MS[0] = core.NewMerkleSquare(19)

	time1 := time.Now()
	data := "this is a medical data, which contains many many hard core medical worlds. this is a medical data, which contains many many hard core medical worlds. this is a medical data, which contains many many hard core medical worlds. this is a medical data, which contains many many hard core medical worlds. this is a medical data, which contains"
	keyword := strings.Split(data, " ")

	time2 := time.Now()
	for _, kw := range keyword {
		// 检查关键字是否存在，不存在添加关键字
		nonexistenceProof := crypto.Hash([]byte(kw), []byte(kw))

		time2_1 := time.Now()
		MS[0].Append([]byte(kw), nonexistenceProof, key1)
		time2_2 := time.Now()

		totalTime += time2_2.Sub(time2_1)
		if keywordExistence[0] == nil {
			keywordExistence[0] = make(map[string][]uint32)
		}

		keywordExistence[0][kw] = append(keywordExistence[0][kw], MS[0].Size-1)
	}

	time3 := time.Now()

	initTime := time1.Sub(time0)
	updateTime := time3.Sub(time2)
	totalTime = totalTime / time.Duration(len(keyword))

	fmt.Printf("One record Index init %s, and update: %s \n", initTime, updateTime)
}

func TestIndexConstruction() {
	// 设置数据库连接信息
	db, err := sqlx.Open("mysql", "root:root1234@tcp(localhost:3306)/foo")
	if err != nil {
		log.Fatal(err)
	}

	// defer关闭数据库连接
	defer db.Close()

	// 测试连接
	err = db.Ping()
	if err != nil {
		log.Fatal(err)
	}

	// 执行查询
	rows, err := db.Queryx("SELECT * FROM Vedrfolnir LIMIT 10000")
	if err != nil {
		log.Fatal(err)
	}
	defer rows.Close()

	// 遍历查询结果
	totalTime := time.Duration(0)

	i := 0
	for rows.Next() {
		var obs_id int
		var patient_id int
		var concept_name string
		var description string

		totalTimeAData := time.Duration(0)
		// 将查询结果映射到结构体或变量
		err := rows.Scan(&obs_id, &patient_id, &concept_name, &description)
		if err != nil {
			log.Fatal(err)
		}

		// 处理每一行的数据
		// fmt.Printf("patient_id: %d, concept_name: %s, description: %s\n", patient_id, concept_name, description)

		// 如果该数据持有者没有构建索引，初始化索引
		//i, err := strconv.Atoi(patient_id)
		if MS[patient_id] == nil {
			//print("this is an empty user\n")
			MS[patient_id] = core.NewMerkleSquare(14)
		}

		keyword := strings.Split(description, " ")
		conceptNameKeyword := strings.Split(concept_name, " ")
		keyword = append(keyword, conceptNameKeyword...)
		deDupKeyword := removeDuplicates(keyword)

		for j, kw := range deDupKeyword {
			// 随机构建关键字
			kwHashStr := string(crypto.Hash([]byte(kw)))
			lastChar := []byte{kwHashStr[j%len(kwHashStr)]}
			tempKey, _ := crypto.Encrypt(lastChar, key0)
			searchKey := crypto.Hash(tempKey, tempKey)

			time2_1 := time.Now()
			MS[patient_id].Append([]byte(kw), searchKey, key1)
			if keywordExistence[patient_id] == nil {
				keywordExistence[patient_id] = make(map[string][]uint32)
			}
			keywordExistence[patient_id][kw] = append(keywordExistence[patient_id][kw], MS[patient_id].Size-1)
			time2_2 := time.Now()
			totalTimeAData += time2_2.Sub(time2_1)
		}

		totalTime += totalTimeAData
		i++
		if i%1000 == 0 {
			fmt.Printf("Average time cost for each data in %d data: %s \n", i, totalTime/time.Duration(i))
		}
	}

	// 检查查询过程中的错误
	if err := rows.Err(); err != nil {
		log.Fatal(err)
	}
}

func TestIndexInit() {
	time1 := time.Now()
	for i := 0; i < 10000; i++ {
		MS[i] = core.NewMerkleSquare(19)
	}
	time2 := time.Now()
	for i := 0; i < 10000; i++ {
		kw := []byte("alice")
		lastChar := []byte{kw[len(kw)-1]}
		existProof := crypto.Hash(lastChar, key0)
		MS[i].Append(existProof, existProof, existProof)
	}
	time3 := time.Now()
	initTime := time2.Sub(time1)
	updateTime := time3.Sub(time2)
	fmt.Printf("Mutiple index init %s, and update %s \n", initTime, updateTime)
}

func TestIndexVerify() {
	time1 := time.Now()
	kw := "medical"
	//searchKey := crypto.Hash([]byte(kw), []byte(kw))
	exclude := []uint32{}

	pos := keywordExistence[0][kw]
	proof, _ := MS[0].GenerateBatchedLookupProof(0, MS[0].Size, []byte(kw), pos)

	keyHashes := MS[0].GenerateKeyHash([]byte(kw), exclude...)

	digest := MS[0].GetOldDigest(MS[0].Size)

	res, _ := core.VerifyBatchedLookupProof(0, []byte(kw), keyHashes, digest, proof)

	print(res, "\n")

	time2 := time.Now()

	verifyTime := time2.Sub(time1)

	fmt.Printf("One index verify: %s \n", verifyTime)
}

func TestIndexVerifyBandwidth() {
	time0 := time.Now()
	kw := "alice"
	exclude := []uint32{}
	keyHashes := MS[0].GenerateKeyHash([]byte(kw), exclude...)
	proof, _ := MS[0].GenerateBatchedLookupProof(0, MS[0].Size, []byte(kw), keywordExistence[0][kw])
	res, _ := core.VerifyBatchedLookupProof(0, []byte("key3"), keyHashes, MS[0].GetDigest(), proof)
	print(res)

	size1 := unsafe.Sizeof(proof)
	size2 := unsafe.Sizeof(kw)

	time1 := time.Now()

	timeCost := time1.Sub(time0)
	fmt.Printf("Size of MyStruct object: %d, %d bytes. Cost time is %s \n", size1, size2, timeCost)
}

func TestIndexVerifyTimeSpaceAll() {
	var proofStorage uintptr
	var keyStorage uintptr
	var verifyTime = time.Duration(0)
	for patient_id, aMS := range MS {
		// 对每个Merkel^2，记录其所需要的密钥大小和存储开销
		var proofStorageApatient uintptr
		var keyStorageApatient uintptr
		var verifyTimeApatient = time.Duration(0)

		for kw, kwPosition := range keywordExistence[patient_id] {
			time0 := time.Now()
			exclude := []uint32{}
			keyHashes := aMS.GenerateKeyHash([]byte(kw), exclude...)
			proof, _ := aMS.GenerateBatchedLookupProof(0, aMS.Size, []byte(kw), kwPosition)

			core.VerifyBatchedLookupProof(0, []byte(kw), keyHashes, aMS.GetDigest(), proof)
			//print(res, "\n")
			time1 := time.Now()

			verifyTimeApatient += time1.Sub(time0)
			proofStorageApatient += unsafe.Sizeof(proof)
			keyStorageApatient += unsafe.Sizeof(keyHashes) * uintptr(len(kwPosition))
		}
		//fmt.Printf("Patient: %d, verify time:  %s, and storage cost: %d bytes. \n", patient_id, verifyTimeApatient, proofStorageApatient+keyStorageApatient)
		proofStorage += proofStorageApatient
		keyStorage += keyStorageApatient
		verifyTime += verifyTimeApatient
	}
	fmt.Printf("Verify time:  %s, and storage cost: %d (proof) + %d (key) =  %d bytes. \n", verifyTime, proofStorage, keyStorage, proofStorage+keyStorage)

}

func removeDuplicates(slice []string) []string {
	encountered := map[string]bool{}
	var result []string

	for _, v := range slice {
		if encountered[v] == false {
			encountered[v] = true
			result = append(result, v)
		}
	}

	return result
}
