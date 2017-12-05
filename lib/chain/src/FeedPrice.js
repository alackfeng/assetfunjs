import {Apis} from "assetfunjs-ws";

/////////////////////////////////////////////////////////////////////////////////////////////
//@brief 从区块链见证人节点获取某个时间某个网站某个交易对的喂价
//
//@coin_name 交易对分子
//@base  交易对分母
//@time  时间，精确到分钟，秒为0
//
//@return 返回对应的喂价价格
////////////////////////////////////////////////////////////////////////////////////////////

function GetFeedPrice(coin_name, base, time){
	return new Promise(function(resolve, reject){
        Apis.instance().db_api().exec("get_coin_price", [coin_name, base, time]).then(function(price){
            if (price) {
                console.log(price);
                resolve(price);
            }else{
                reject(new Error("there is no price" + coin_name + "," + base + "," + time));
            }
        })
    })
}

function GetLatestValidPrice(platform, quote_base){
    return new Promise(function(resolve, reject){
        Apis.instance().db_api().exec("get_latest_valid_price", [platform, quote_base]).then(function(price){
            if (price) {
                console.log(price);
                resolve(price);
            }else{
                reject(new Error("there is no price" + platform + "," + quote_base));
            }
        })
    })
}

function GetLatestValidPriceBatch(query_items){
    return new Promise(function(resolve, reject){
        Apis.instance().db_api().exec("get_latest_valid_price_batch", [query_items]).then(function(price_items){
            if (price_items) {
                console.log("price_items: ", price_items);
                resolve(price_items);
            }else{
                reject(new Error("there is no price: " + query_items));
            }
        })
    })
}

/* for future
function GetFeedPrice(quote, base, src, time){
    return new Promise(function(resolve, reject){
        Apis.instance().db_api().exec("get_coin_price", [Id]).then(function(price){
            if (price) {
                console.log(price);
                resolve(price);
            }else{
                reject(new Error("there is no price" + Id));
            }
        })
    })
}
*/

export {GetFeedPrice, GetLatestValidPrice, GetLatestValidPriceBatch}