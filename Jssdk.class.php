<?php
/**
 * Created by PhpStorm.
 * User: ibestlove
 * Date: 2016/9/24
 * Time: 11:08
 */

namespace Com;

defined('JSAPI_TICKET') || define('JSAPI_TICKET', 'jsapi_ticket_');

interface JsApiTicket
{
    public function getJsApiTicket($appId, $appSecret);
}

class TicketGetBase
{
    /**
     * curl采集
     * @param $url请求
     * @return mixed 采集的内容
     */
    protected function httpGet($url)
    {
        $curl = curl_init();
        curl_setopt($curl, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($curl, CURLOPT_TIMEOUT, 500);
        // 为保证第三方服务器与微信服务器之间数据传输的安全性，所有微信接口采用https方式调用，必须使用下面2行代码打开ssl安全校验。
        // 如果在部署过程中代码在此处验证失败，请到 http://curl.haxx.se/ca/cacert.pem 下载新的证书判别文件。
        curl_setopt($curl, CURLOPT_SSL_VERIFYPEER, true);
        curl_setopt($curl, CURLOPT_SSL_VERIFYHOST, true);
        curl_setopt($curl, CURLOPT_URL, $url);

        $res = curl_exec($curl);
        curl_close($curl);

        return $res;
    }
}

class TicketGetWithDb extends TicketGetBase implements JsApiTicket
{
    public function getJsApiTicket($appId, $appSecret)
    {
        // TODO: Implement getJsApiTicket() method.
        $condition = array('app_id' => $appId, 'app_secret' => $appSecret);
        $jsapi_ticket_set = M('jsapi_ticket')->where($condition)->find();//获取数据
        if ($jsapi_ticket_set) {
            //检查是否超时，超时了重新获取
            if ($jsapi_ticket_set['expires_in'] > time()) {
                //未超时，直接返回jsapi_ticket
                return $jsapi_ticket_set['jsapi_ticket'];
            } else {
                //已超时，重新获取
                $wechatAuth = new WechatAuth($appId, $appSecret);
                $token = $wechatAuth->getAccessToken(new TokenGetWithDb());
                // 如果是企业号用以下 URL 获取 ticket
                // $url = "https://qyapi.weixin.qq.com/cgi-bin/get_jsapi_ticket?access_token=$accessToken";
                $url = "https://api.weixin.qq.com/cgi-bin/ticket/getticket?type=jsapi&access_token={$token['access_token']}";
                $res = json_decode($this->httpGet($url));
                $ticket = $res->ticket;
                $expires_in = time() + intval($res->expires_in);
                $data['jsapi_ticket'] = $ticket;
                $data['expires_in'] = $expires_in;
                $data['updated_at'] = time();
                M('jsapi_ticket')->where($condition)->save($data);//更新数据
            }
        } else {
            //第一次获取jsapi_ticket
            $wechatAuth = new WechatAuth($appId, $appSecret);
            $token = $wechatAuth->getAccessToken(new TokenGetWithDb());
            // 如果是企业号用以下 URL 获取 ticket
            // $url = "https://qyapi.weixin.qq.com/cgi-bin/get_jsapi_ticket?access_token=$accessToken";
            $url = "https://api.weixin.qq.com/cgi-bin/ticket/getticket?type=jsapi&access_token={$token['access_token']}";
            $res = json_decode($this->httpGet($url));
            $ticket = $res->ticket;
            $expires_in = time() + intval($res->expires_in);
            $m = M('jsapi_ticket');
            $data['app_id'] = $appId;
            $data['app_secret'] = $appSecret;
            $data['jsapi_ticket'] = $ticket;
            $data['expires_in'] = $expires_in;
            $data['created_at'] = time();
            $data['updated_at'] = time();
            $m->add($data);//更新数据
        }

        return $ticket;
    }
}

class TicketGetWithRedis extends TicketGetBase implements JsApiTicket
{
    public function getJsApiTicket($appId, $appSecret)
    {
        // TODO: Implement getJsApiTicket() method.
        //自动加载redis
        \Predis\Autoloader::register();
        $redis = new \Predis\Client(C('REDIS_SERVER'));
        // jsapi_ticket 应该全局存储与更新，以下代码以写入到文件中做示例
        if (!$redis->get(JSAPI_TICKET . $appId)) {//redis中对应jsapi_ticket不存在则重新获取
            $wechatAuth = new WechatAuth($appId, $appSecret);
            $token = $wechatAuth->getAccessToken(new TokenGetWithRedis());
            // 如果是企业号用以下 URL 获取 ticket
            // $url = "https://qyapi.weixin.qq.com/cgi-bin/get_jsapi_ticket?access_token=$accessToken";
            $url = "https://api.weixin.qq.com/cgi-bin/ticket/getticket?type=jsapi&access_token={$token['access_token']}";
            $res = json_decode($this->httpGet($url));
            $ticket = $res->ticket;
            //将jsapi_ticket以有效时间为7000秒存储至redis
            $redis->setex(JSAPI_TICKET . $appId, 7000, $ticket);
        } else {//存在则直接赋值
            $ticket = $redis->get(JSAPI_TICKET . $appId);
        }

        return $ticket;
    }
}

class TicketGetWithFile extends TicketGetBase implements JsApiTicket
{
    public function getJsApiTicket($appId, $appSecret)
    {
        $jsapiTicketFilePath = 'Runtime/'.JSAPI_TICKET.$appId.'.php';
        // TODO: Implement getJsApiTicket() method.
        // jsapi_ticket 应该全局存储与更新，以下代码以写入到文件中做示例
        $data = json_decode($this->get_php_file($jsapiTicketFilePath));
        if ($data->expire_time < time()) {
            $wechatAuth = new WechatAuth($appId, $appSecret);
            $token = $wechatAuth->getAccessToken(new TokenGetWithFile());
            // 如果是企业号用以下 URL 获取 ticket
            // $url = "https://qyapi.weixin.qq.com/cgi-bin/get_jsapi_ticket?access_token=$accessToken";
            $url = "https://api.weixin.qq.com/cgi-bin/ticket/getticket?type=jsapi&access_token={$token['access_token']}";
            $res = json_decode($this->httpGet($url));
            $ticket = $res->ticket;
            if ($ticket) {
                $data->expire_time = time() + 7000;
                $data->jsapi_ticket = $ticket;
                $this->set_php_file($jsapiTicketFilePath, json_encode($data));
            }
        } else {
            $ticket = $data->jsapi_ticket;
        }

        return $ticket;
    }

    private function get_php_file($filename)
    {
        return trim(substr(file_get_contents($filename), 15));
    }

    private function set_php_file($filename, $content)
    {
        $fp = fopen($filename, "w");
        fwrite($fp, "<?php exit();?>" . $content);
        fclose($fp);
    }
}

class Jssdk
{
    private $appId;
    private $appSecret;
    private $restApi;//true 仅是接口（前后端完全分离） false 后端渲染

    public function __construct($appId, $appSecret, $restApi = false)
    {
        $this->appId = $appId;
        $this->appSecret = $appSecret;
        $this->restApi = $restApi;
    }

    /**
     * JSSDK开发获取签名信息
     * @param string $from access_token和jsapi_ticket存储类型
     * @return array
     */
    public function getSignPackage(JsApiTicket $apiTicket)
    {
        $jsapiTicket = $apiTicket->getJsApiTicket($this->appId, $this->appSecret);
        // 注意 URL 一定要动态获取，不能 hardcode.
        $protocol = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off' || $_SERVER['SERVER_PORT'] == 443) ? "https://" : "http://";
        $url = "$protocol$_SERVER[HTTP_HOST]$_SERVER[REQUEST_URI]";

        //前后分离时，需要使用前端的URL加密
        if($this->restApi && isset($_SERVER['HTTP_REFERER'])){
            $url = $_SERVER['HTTP_REFERER'];
        }

        $timestamp = time();
        $nonceStr = $this->createNonceStr();

        // 这里参数的顺序要按照 key 值 ASCII 码升序排序
        $string = "jsapi_ticket=$jsapiTicket&noncestr=$nonceStr&timestamp=$timestamp&url=$url";

        $signature = sha1($string);

        $signPackage = array(
            "appId" => $this->appId,
            "nonceStr" => $nonceStr,
            "timestamp" => $timestamp,
            "url" => $url,
            "signature" => $signature,
            //"rawString" => $string
        );
        return $signPackage;
    }

    /**
     * 创建指定长度的随机字符串
     * @param int $length 字符长度
     * @return string 签名随机16位字符串
     */
    private function createNonceStr($length = 16)
    {
        $chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        $str = "";
        for ($i = 0; $i < $length; $i++) {
            $str .= substr($chars, mt_rand(0, strlen($chars) - 1), 1);
        }
        return $str;
    }
}