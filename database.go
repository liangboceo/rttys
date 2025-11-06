/*
 * @Author: 周家建
 * @Mail: zhou_0611@163.com
 * @Date: 2021-07-27 19:02:39
 * @Description:
 */

package main

import (
	"database/sql"
	"rttys/utils"
	"strings"
	"sync"
	"time"

	_ "github.com/go-sql-driver/mysql"
	_ "modernc.org/sqlite"
)

var databasePool sync.Map
var once sync.Once
var cleanupTicker *time.Ticker

func instanceDB(str string) (*sql.DB, error) {
	defer func() {
		utils.ErrorHandle()
	}()
	sp := strings.Split(str, "://")
	once.Do(func() {
		cleanupTicker = time.NewTicker(5 * time.Minute)
		go cleanupDatabase()
	})
	if len(sp) == 2 {
		if database, ok := databasePool.Load(sp[0]); ok {
			return database.(*sql.DB), nil
		}
		database, err := sql.Open(sp[0], sp[1])
		if err != nil {
			return database, err
		}
		databasePool.Store(sp[0], database)
		return database, nil
	} else {
		if database, ok := databasePool.Load("mysql"); ok {
			return database.(*sql.DB), nil
		}
		database, err := sql.Open("mysql", str)
		if err != nil {
			return database, err
		}
		databasePool.Store(sp[0], database)
		return database, nil
	}
}
func cleanupDatabase() {
	for range cleanupTicker.C {
		databasePool.Range(func(key, value any) bool {
			database := value.(*sql.DB)
			if database.Stats().OpenConnections == 0 {
				_ = database.Close()
				databasePool.Delete(key)
			}
			return true
		})
	}
}
