import assert from "assert";
//import SubjectQuery from "../../lib";
import {Apis, ChainConfig} from "assetfunjs-ws";
//import {GetSubjectsByName} from "../../lib/chain/src/SubjectQuery"
import {GetSubjectById, GetSubjectsByName, GetSubjectsOrderById, 
    GetSubjectsByStatus, GetSubjectsByCreator, GetSubjectsByCreateTime, 
    GetSubjectsByVoteEndTime, GetSubjectVotesByVoter, GetSubjectVotesBySubjectId, 
    GetSubjectEventsBySubjectId, GetSubjectEventsByOperator,
    FrontPageGetSubjects,MarketGetSubjects,MyGetSubjects,GetMyCreateSubjects } from "../../lib"

describe("SubjectQuery functions test", () => {

	//let cs = "ws://106.15.202.130:11013";
  let cs = "ws://192.168.1.221:11011";
	before(function() {
            return Apis.instance(cs, true).init_promise.then(function (result) {
                console.log("conneted to ws://192.168.1.221:11011")
            });
        });

	it("Get subjects by name", function(){
        return new Promise(function(resolve, reject){
            GetSubjectsByName(1,10,"bitcoin_up_20006").then(function(subjects){
           		console.log(subjects);
                if (subjects) {
           		    resolve()
                }else{
           			reject(Error("there is no subject named bitcoin_up_20006."))
           		}	
           })
        })
    })

    
    it("Get subjects order by id", function(){
        return new Promise(function(resolve, reject){
            GetSubjectsOrderById(1,10).then(function(subjects){
           		console.log(subjects);
                if (subjects) {
           		    resolve()
                }else{
           			reject(Error("there is no subject named bitcoin_up_20006."))
           		}	
           })
        })
    })
    
    it("Get subjects by status", function(){
        return new Promise(function(resolve, reject){
            GetSubjectsByStatus(1,10,"create_status").then(function(subjects){
           		console.log(subjects);
                if (subjects) {
           		    resolve()
                }else{
           			reject(Error("there is no subject named bitcoin_up_20006."))
           		}	
           })
        })
    })

    it("Get subjects by creat time", function(){
        return new Promise(function(resolve, reject){
            GetSubjectsByCreateTime(1,10,"2017-10-20T07:14:57","2017-10-21T07:14:57").then(function(subjects){
           		console.log(subjects);
                if (subjects) {
           		    resolve()
                }else{
           			reject(Error("there is no subject named bitcoin_up_20006."))
           		}	
           })
        })
    })

    it("Get subjects by vote end time", function(){
        return new Promise(function(resolve, reject){
            GetSubjectsByVoteEndTime(1,10,"2018-01-13T19:46:04","2019-01-13T19:46:04").then(function(subjects){
           		console.log(subjects);
                if (subjects) {
           		    resolve()
                }else{
           			reject(Error("there is no subject named bitcoin_up_20006."))
           		}	
           })
        })
    })

    it("Market get subjects by vote end time", function(){
        return new Promise(function(resolve, reject){
            MarketGetSubjects({"start":1,"limit":5,"start_time":"1970-01-01T00:00:00","end_time":"2018-11-03T11:12:27","direction":2,"order_by":"create_time","platform_quote_base":{"quote_base":"BTC/USD","platform_id": "1000001"},"status":"all","account_name_or_id":"nathan"}).then(function(subjects){
              console.log(subjects);
                if (subjects) {
                  resolve()
                }else{
                reject(Error("there is no subjects."))
              } 
           })
        })
    })

    it("My get subjects", function(){
        return new Promise(function(resolve, reject){
            MyGetSubjects({"start":1,"limit":100,"start_time":"2017-11-02T12:00","end_time":"2018-12-10T12:00","direction":1,"order_by":"vote_end_time","platform_quote_base":{"quote_base":"BTC/USD","platform_id": "1000001"},"status":"all","account_name_or_id":"nathan"}).then(function(subjects){
              console.log(subjects);
                if (subjects) {
                  resolve()
                }else{
                reject(Error("there is no subjects."))
              } 
           })
        })
    })

    it("Get my create subjects", function(){
        return new Promise(function(resolve, reject){
            GetMyCreateSubjects({"start":1,"limit":100,"start_time":"2017-11-02T12:00","end_time":"2018-12-10T12:00","direction":2,"order_by":"create_time","platform_quote_base":{"quote_base":"BTC/USD","platform_id": "1000001"},"status":"all","account_name_or_id":"nathan"}).then(function(subjects){
              console.log(subjects);
                if (subjects) {
                  resolve()
                }else{
                reject(Error("there is no subjects."))
              } 
           })
        })
    })

    it("Get subject by id", function(){
        return new Promise(function(resolve, reject){
            GetSubjectById("nathan", "1.16.0").then(function(subjects){
              console.log(subjects);
                if (subjects) {
                  resolve()
                }else{
                reject(Error("there is no subjects."))
              } 
           })
        })
    })

    it("Get subjects by creator", function(){
        return new Promise(function(resolve, reject){
            GetSubjectsByCreator({"start":1,"limit":100,"start_time":"2017-11-02T12:00","end_time":"2018-12-10T12:00","direction":1,"order_by":"create_time","platform_quote_base":{"quote_base":"ALL","platform_id": "0000000"},"status":"all","account_name_or_id":"nathan"}, "nathan").then(function(subjects){
              console.log(subjects);
                if (subjects) {
                  resolve()
                }else{
                reject(Error("there is no subjects."))
              } 
           })
        })
    })

    

    
})