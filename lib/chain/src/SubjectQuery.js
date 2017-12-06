import {Apis} from "assetfunjs-ws";

function GetSubjectsByName(startId, limit, name){
	return new Promise(function(resolve, reject){
        Apis.instance().db_api().exec("get_subjects_by_name", [startId, limit, name]).then(function(subjects){
            if (subjects.length > 0) {
                console.log(subjects);
                console.log(subjects.length);
                resolve(subjects);
            }else{
                reject(new Error("there is no subject whose name is " + name));
            }
        })
    })
}

function GetSubjectsOrderById(startId, limit){
	return new Promise(function(resolve, reject){
        Apis.instance().db_api().exec("get_subjects_order_by_id", [startId,limit]).then(function(subjects){
            if (subjects.length > 0) {
                console.log(subjects);
                console.log(subjects.length)
                resolve(subjects);
            }else{
                reject(new Error("there is no subject."));
            }
        })
    })
}
function GetSubjectsByStatus(startId, limit, status){
	return new Promise(function(resolve, reject){
        Apis.instance().db_api().exec("get_subjects_by_status", [startId, limit, status]).then(function(subjects){
            if (subjects.length > 0) {
                console.log(subjects);
                console.log(subjects.length)
                resolve(subjects);
            }else{
                reject(new Error("there is no subject whose status is create_status."));
            }
        })
    })
}

function GetSubjectsByCreateTime(startId, limit, startTime, endTime){
	return new Promise(function(resolve, reject){
        Apis.instance().db_api().exec("get_subjects_by_creator_time", [startId, limit, startTime, endTime]).then(function(subjects){
            if (subjects.length > 0) {
                console.log(subjects);
                console.log(subjects.length)
                resolve(subjects);
            }else{
                reject(new Error("there is no subject whose create time is 2017-10-20T07:14:57."));
                }
            })
    })
}

function GetSubjectsByVoteEndTime(startId, limit, startTime, endTime){
	return new Promise(function(resolve, reject){
        Apis.instance().db_api().exec("get_subjects_by_vote_end_time", [startId, limit, startTime, endTime]).then(function(subjects){
            if (subjects.length > 0) {
                console.log(subjects);
                console.log(subjects.length)
                resolve(subjects);
            }else{
                reject(new Error("there is no subject whose vote end time is 2018-01-13T19:46:04."));
            }
        })
    })
}

//not tested
function GetSubjectVotesByVoter(startId, limit, voter){
    return new Promise(function(resolve, reject){
        Apis.instance().db_api().exec("get_subject_votes_by_voter", [startId, limit, voter]).then(function(subjectVotes){
            if (subjectVotes.length > 0) {
                console.log(subjectVotes);
                console.log(subjectVotes.length)
                resolve(subjectVotes);
            }else{
                reject(new Error("there is no subject whose vote end time is 2018-01-13T19:46:04."));
            }
        })
    })
}

function GetSubjectVotesBySubjectId(startId, limit, subjectId){
    return new Promise(function(resolve, reject){
        Apis.instance().db_api().exec("get_subject_votes_by_subject_id", [startId, limit, subjectId]).then(function(subjectVotes){
            if (subjectVotes.length > 0) {
                console.log(subjectVotes);
                console.log(subjectVotes.length)
                resolve(subjectVotes);
            }else{
                reject(new Error("there is no subject whose vote end time is 2018-01-13T19:46:04."));
            }
        })
    })
}

function GetSubjectEventsBySubjectId(startId, limit, subjectId){
    return new Promise(function(resolve, reject){
        Apis.instance().db_api().exec("get_subject_votes_by_subject_id", [startId, limit, subjectId]).then(function(subjectEvents){
            if (subjectEvents.length > 0) {
                console.log(subjectEvents);
                console.log(subjectEvents.length)
                resolve(subjectEvents);
            }else{
                reject(new Error("there is no subject event by subject id" + subjectId));
            }
        })
    })
}

function GetSubjectEventsByOperator(startId, limit, operatorId){
    return new Promise(function(resolve, reject){
        Apis.instance().db_api().exec("get_subject_events_by_operator", [startId, limit, operatorId]).then(function(subjectEvents){
            if (subjectEvents.length > 0) {
                console.log(subjectEvents);
                console.log(subjectEvents.length)
                resolve(subjectEvents);
            }else{
                reject(new Error("there is no subject event by." + operatorId));
            }
        })
    })
    
}

function FrontPageGetSubjects(condition){
    return new Promise(function(resolve, reject){
        Apis.instance().db_api().exec("front_page_get_subjects", [condition]).then(function(subjects){
            if (subjects.length >= 0) {
                console.log(subjects);
                console.log(subjects.length)
                resolve(subjects);
            }else{
                reject(new Error("there is no subjects."));
            }
        })
    })
    
}

function MarketGetSubjects(condition){
    return new Promise(function(resolve, reject){
        Apis.instance().db_api().exec("market_get_subjects", [condition]).then(function(subjects){
            if (subjects.length >= 0) {
                console.log(subjects);
                console.log(subjects.length)
                resolve(subjects);
            }else{
                reject(new Error("there is no subjects."));
            }
        })
    })
    
}

function MyGetSubjects(condition){
    return new Promise(function(resolve, reject){
        Apis.instance().db_api().exec("my_get_subjects", [condition]).then(function(subjects){
            if (subjects.length >= 0) {
                console.log(subjects);
                console.log(subjects.length)
                resolve(subjects);
            }else{
                reject(new Error("there is no subjects."));
            }
        })
    })
}

function GetMyCreateSubjects(condition){
    return new Promise(function(resolve, reject){
        Apis.instance().db_api().exec("get_my_create_subjects", [condition]).then(function(subjects){
            if (subjects.length >= 0) {
                console.log(subjects);
                console.log(subjects.length)
                resolve(subjects);
            }else{
                reject(new Error("there is no subjects."));
            }
        })
    })
}

function GetSubjectById(accountNameOrId, subjectId){
    return new Promise(function(resolve, reject){
        Apis.instance().db_api().exec("get_subject_by_id", [accountNameOrId, subjectId]).then(function(subjects){
           if (subjects.length >= 0) {
                console.log(subjects);
                console.log(subjects.length)
                resolve(subjects);
            }else{
                reject(new Error("there is no subject."));
            }
        })
    })
}

function GetSubjectsByCreator(condition, creatorNameOrId){
    return new Promise(function(resolve, reject){
        Apis.instance().db_api().exec("get_subjects_by_creator", [condition, creatorNameOrId]).then(function(subjects){
            if (subjects.length >= 0) {
                console.log(subjects);
                console.log(subjects.length)
                resolve(subjects);
            }else{
                reject(new Error("there is no subject."));
            }
        })
    })
}

export {GetSubjectById, GetSubjectsByName, GetSubjectsOrderById, 
    GetSubjectsByStatus, GetSubjectsByCreator, GetSubjectsByCreateTime, 
    GetSubjectsByVoteEndTime, GetSubjectVotesByVoter, GetSubjectVotesBySubjectId, 
    GetSubjectEventsBySubjectId, GetSubjectEventsByOperator,
    FrontPageGetSubjects,MarketGetSubjects,MyGetSubjects,GetMyCreateSubjects
}