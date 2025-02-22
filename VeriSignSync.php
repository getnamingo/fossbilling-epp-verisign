<?php

require_once __DIR__ . '/load.php';
$di = include __DIR__ . '/di.php';

$dbConfig = \FOSSBilling\Config::getProperty('db', []);
$registrar = "VeriSign";

try
{
    // Establish the PDO connection
    $dsn = $dbConfig["type"] . ":host=" . $dbConfig["host"] . ";port=" . $dbConfig["port"] . ";dbname=" . $dbConfig["name"];
    $pdo = new PDO($dsn, $dbConfig["user"], $dbConfig["password"]);
    $stmt = $pdo->prepare("SELECT * FROM tld_registrar WHERE registrar = :registrar");
    $stmt->bindValue(":registrar", $registrar);
    $stmt->execute();
    $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);

    $config = [];

    foreach ($rows as $row)
    {
        $config = json_decode($row["config"], true);
        $registrar_id = $row["id"];
    }

    if (empty($config))
    {
        exit("Database cannot be accessed right now.".PHP_EOL);
    }

}
catch(PDOException $e)
{
    exit("Database error: " . $e->getMessage().PHP_EOL);
}
catch(Exception $e)
{
    exit("General error: " . $e->getMessage().PHP_EOL);
}

function connectEpp($config)
{
    try
    {
        $epp = new eppClient();
        $info = [
        "host" => $config["host"],
        "port" => $config["port"], "timeout" => 30, "tls" => "1.3", "bind" => false, "bindip" => "1.2.3.4:0", "verify_peer" => false, "verify_peer_name" => false,
        "verify_host" => false, "cafile" => "", "local_cert" => $config["ssl_cert"], "local_pk" => $config["ssl_key"], "passphrase" => "", "allow_self_signed" => true, ];
        $epp->connect($info);
        $login = $epp->login(["clID" => $config["username"], "pw" => $config["password"],
        "prefix" => "tembo", ]);
        if (array_key_exists("error", $login))
        {
            exit("Login Error: " . $login["error"]. PHP_EOL);
        }
        else
        {
            echo "Login Result: " . $login["code"] . ": " . $login["msg"][0] . PHP_EOL;
        }
        return $epp;
    }
    catch(EppException $e)
    {
        exit("Error : " . $e->getMessage().PHP_EOL);
    }
}

try {
    // Fetch all domains
    $stmt = $pdo->prepare('SELECT sld, tld FROM service_domain WHERE tld_registrar_id = :registrar');
    $stmt->bindValue(':registrar', $registrar_id);
    $stmt->execute();
    $domains = $stmt->fetchAll(PDO::FETCH_ASSOC);
    
    $epp = connectEpp($config);

    foreach ($domains as $domainRow) {
        $domain = $domainRow['sld'] . $domainRow['tld'];
        $params = ["domainname" => $domain];
        $domainInfo = $epp->domainInfo($params);

        if (array_key_exists("error", $domainInfo) || (isset($domainInfo['code']) && $domainInfo['code'] == 2303)) {
            if (strpos($domainInfo["error"], "Domain does not exist") !== false || (isset($domainInfo['code']) && $domainInfo['code'] == 2303)) {
                $stmt = $pdo->prepare('DELETE FROM service_domain WHERE sld = :sld AND tld = :tld');
                $stmt->bindValue(':sld', $domainRow['sld']);
                $stmt->bindValue(':tld', $domainRow['tld']);
                $stmt->execute();
            }
            $stmt = $pdo->prepare('SELECT id FROM service_domain WHERE sld = :sld AND tld = :tld');
            $stmt->bindValue(':sld', $domainRow['sld']);
            $stmt->bindValue(':tld', $domainRow['tld']);
            $stmt->execute();
            $serviceDomain = $stmt->fetch(PDO::FETCH_ASSOC);
            if ($serviceDomain) {
                $serviceId = $serviceDomain['id'];
                $stmt = $pdo->prepare('UPDATE client_order SET canceled_at = :canceled_at, status = :status, reason = :reason WHERE service_id = :service_id');
                $stmt->bindValue(':canceled_at', date('Y-m-d H:i:s'));
                $stmt->bindValue(':status', 'cancelled');
                $stmt->bindValue(':reason', 'domain deleted');
                $stmt->bindValue(':service_id', $serviceId);
                $stmt->execute();
            }
            echo $domainInfo["error"] . " (" . $domain . ")" . PHP_EOL;
            continue;
        }

        $ns = $domainInfo['ns'];

        $ns1 = isset($ns[1]) ? $ns[1] : null;
        $ns2 = isset($ns[2]) ? $ns[2] : null;
        $ns3 = isset($ns[3]) ? $ns[3] : null;
        $ns4 = isset($ns[4]) ? $ns[4] : null;
        
        $exDate = $domainInfo['exDate'];
        $datetime = new DateTime($exDate);
        $formattedExDate = $datetime->format('Y-m-d H:i:s');
        
        $statuses = $domainInfo['status'];

        $clientStatuses = ['clientDeleteProhibited', 'clientTransferProhibited', 'clientUpdateProhibited'];
        $serverStatuses = ['serverDeleteProhibited', 'serverTransferProhibited', 'serverUpdateProhibited'];

        // Check if all client statuses are present in the $statuses array
        $clientProhibited = count(array_intersect($clientStatuses, $statuses)) === count($clientStatuses);

        // Check if all server statuses are present in the $statuses array
        $serverProhibited = count(array_intersect($serverStatuses, $statuses)) === count($serverStatuses);

        if ($clientProhibited || $serverProhibited) {
           $locked = 1;
        } else {
           $locked = 0;
        }

        $sqlCheck = 'SELECT COUNT(*) FROM extension WHERE name = :name AND status = :status';
        $stmtCheck = $pdo->prepare($sqlCheck);
        $stmtCheck->bindValue(':name', 'registrar');
        $stmtCheck->bindValue(':status', 'installed');
        $stmtCheck->execute();
        $count = $stmtCheck->fetchColumn();

        // Prepare the UPDATE statement
        $stmt = $pdo->prepare('UPDATE service_domain SET ns1 = :ns1, ns2 = :ns2, ns3 = :ns3, ns4 = :ns4, expires_at = :expires_at, locked = :locked, synced_at = :synced_at, transfer_code = :transfer_code WHERE sld = :sld AND tld = :tld');
        $stmt->bindValue(':ns1', $ns1);
        $stmt->bindValue(':ns2', $ns2);
        $stmt->bindValue(':ns3', $ns3);
        $stmt->bindValue(':ns4', $ns4);
        $stmt->bindValue(':expires_at', $formattedExDate);
        $stmt->bindValue(':locked', $locked);
        $stmt->bindValue(':synced_at', date('Y-m-d H:i:s'));
        $stmt->bindValue(':transfer_code', $domainInfo["authInfo"]);
        $stmt->bindValue(':sld', $domainRow['sld']);
        $stmt->bindValue(':tld', $domainRow['tld']);
        $stmt->execute();
        
        $stmt = $pdo->prepare('SELECT id FROM service_domain WHERE sld = :sld AND tld = :tld');
        $stmt->bindValue(':sld', $domainRow['sld']);
        $stmt->bindValue(':tld', $domainRow['tld']);
        $stmt->execute();
        $serviceDomain = $stmt->fetch(PDO::FETCH_ASSOC);
        
        if ($serviceDomain) {
            $serviceId = $serviceDomain['id'];
            $stmt = $pdo->prepare('UPDATE client_order SET expires_at = :expires_at WHERE service_id = :service_id');
            $stmt->bindValue(':expires_at', $formattedExDate);
            $stmt->bindValue(':service_id', $serviceId);
            $stmt->execute();
        }
       
        if ($count > 0) {
            $selectStmt = $pdo->prepare('SELECT id FROM service_domain WHERE sld = :sld AND tld = :tld LIMIT 1');
            $selectStmt->bindValue(':sld', $domainRow['sld']);
            $selectStmt->bindValue(':tld', $domainRow['tld']);
            $selectStmt->execute();
            $domainId = $selectStmt->fetchColumn();

            $sqlMeta = '
                INSERT INTO domain_meta (domain_id, registry_domain_id, registrant_contact_id, admin_contact_id, tech_contact_id, billing_contact_id, created_at, updated_at)
                VALUES (:domain_id, :registry_domain_id, :registrant_contact_id, :admin_contact_id, :tech_contact_id, :billing_contact_id, NOW(), NOW())
                ON DUPLICATE KEY UPDATE
                    registry_domain_id = VALUES(registry_domain_id),
                    registrant_contact_id = VALUES(registrant_contact_id),
                    admin_contact_id = VALUES(admin_contact_id),
                    tech_contact_id = VALUES(tech_contact_id),
                    billing_contact_id = VALUES(billing_contact_id),
                    updated_at = NOW();
            ';
            $stmtMeta = $pdo->prepare($sqlMeta);
            $stmtMeta->bindValue(':domain_id', $domainId);
            $stmtMeta->bindValue(':registry_domain_id', $domainInfo['roid']);
            $registrant_contact_id = null;
            $admin_contact_id = null;
            $tech_contact_id = null;
            $billing_contact_id = null;
            $stmtMeta->bindValue(':registrant_contact_id', $registrant_contact_id);
            $stmtMeta->bindValue(':admin_contact_id', $admin_contact_id);
            $stmtMeta->bindValue(':tech_contact_id', $tech_contact_id);
            $stmtMeta->bindValue(':billing_contact_id', $billing_contact_id);
            $stmtMeta->execute();

            $status = $domainInfo['status'] ?? 'No status available';
            $sqlStatus = '
                INSERT INTO domain_status (domain_id, status, created_at)
                VALUES (:domain_id, :status, NOW())
                ON DUPLICATE KEY UPDATE
                    status = VALUES(status),
                    created_at = NOW();
            ';
            $stmtStatus = $pdo->prepare($sqlStatus);

            if (is_array($status)) {
                foreach ($status as $singleStatus) {
                    $stmtStatus->bindValue(':domain_id', $domainId);
                    $stmtStatus->bindValue(':status', $singleStatus);
                    $stmtStatus->execute();
                }
            } else {
                $stmtStatus->bindValue(':domain_id', $domainId);
                $stmtStatus->bindValue(':status', $status);
                $stmtStatus->execute();
            }
        }
        echo "Update successful for domain: " . $domain . PHP_EOL;
    }

    $logout = $epp->logout();
    echo "Logout Result: " . $logout["code"] . ": " . $logout["msg"][0] . PHP_EOL;
} catch (PDOException $e) {
    exit("Database error: " . $e->getMessage().PHP_EOL);
} catch(EppException $e) {
    exit("Error: " . $e->getMessage().PHP_EOL);
}

// Mini EPP Client Class
class eppClient
{
    private $resource;
    private $isLoggedIn;
    private $prefix;

    public function __construct()
    {
        if (!extension_loaded('SimpleXML')) {
            exit('PHP extension SimpleXML is not loaded.'.PHP_EOL);
        }
    }

    /**
     * connect
     */
    public function connect($params = array())
    {
        $host = (string)$params['host'];
        $port = (int)$params['port'];
        $timeout = (int)$params['timeout'];
        $tls = (string)$params['tls'];
        $bind = (string)$params['bind'];
        $bindip = (string)$params['bindip'];
        if ($tls !== '1.3' && $tls !== '1.2' && $tls !== '1.1') {
            exit('Invalid TLS version specified.'.PHP_EOL);
        }
        $opts = array(
            'ssl' => array(
            'verify_peer' => (bool)$params['verify_peer'],
            'verify_peer_name' => (bool)$params['verify_peer_name'],
            'verify_host' => (bool)$params['verify_host'],
            'cafile' => (string)$params['cafile'],
            'local_cert' => (string)$params['local_cert'],
            'local_pk' => (string)$params['local_pk'],
            'passphrase' => (string)$params['passphrase'],
            'allow_self_signed' => (bool)$params['allow_self_signed'],
            'min_tls_version' => $tls
            )
        );
        if ($bind) {
            $opts['socket'] = array('bindto' => $bindip);
        }
        $context = stream_context_create($opts);
        $this->resource = stream_socket_client("tls://{$host}:{$port}", $errno, $errmsg, $timeout, STREAM_CLIENT_CONNECT, $context);
        if (!$this->resource) {
            exit("Cannot connect to server '{$host}': {$errmsg}".PHP_EOL);
        }

        return $this->readResponse();
    }

    /**
     * readResponse
     */
    public function readResponse()
    {
        $hdr = stream_get_contents($this->resource, 4);
        if ($hdr === false) {
            exit('Connection appears to have closed.'.PHP_EOL);
        }
        if (strlen($hdr) < 4) {
            exit('Failed to read header from the connection.'.PHP_EOL);
        }
        $unpacked = unpack('N', $hdr);
        $xml = fread($this->resource, ($unpacked[1] - 4));
        $xml = preg_replace('/></', ">\n<", $xml);
        $this->_response_log($xml);
        return $xml;
    }

    /**
     * writeRequest
     */
    public function writeRequest($xml)
    {
        $this->_request_log($xml);
        if (fwrite($this->resource, pack('N', (strlen($xml) + 4)) . $xml) === false) {
            exit('Error writing to the connection.'.PHP_EOL);
        }
        $xml_string = $this->readResponse();
        libxml_use_internal_errors(true);
        
        $r = simplexml_load_string($xml_string, 'SimpleXMLElement', LIBXML_DTDLOAD | LIBXML_NOENT);
        if ($r instanceof SimpleXMLElement) {
            $r->registerXPathNamespace('e', 'urn:ietf:params:xml:ns:epp-1.0');
            $r->registerXPathNamespace('xsi', 'http://www.w3.org/2001/XMLSchema-instance');
            $r->registerXPathNamespace('domain', 'urn:ietf:params:xml:ns:domain-1.0');
            $r->registerXPathNamespace('contact', 'urn:ietf:params:xml:ns:contact-1.0');
            $r->registerXPathNamespace('host', 'urn:ietf:params:xml:ns:host-1.0');
            $r->registerXPathNamespace('rgp', 'urn:ietf:params:xml:ns:rgp-1.0');
        }
        if (isset($r->response) && $r->response->result->attributes()->code >= 2000) {
            echo $r->response->result->msg.PHP_EOL;
        }
        return $r;
    }

    /**
     * disconnect
     */
    public function disconnect()
    {
        if (!fclose($this->resource)) {
            exit('Error closing the connection.'.PHP_EOL);
        }
        $this->resource = null;
    }

    /**
    * wrapper for functions
    */
    public function __call($func, $args)
    {
        if (!function_exists($func)) {
            exit("Call to undefined method Epp::$func().".PHP_EOL);
        }

        if ($func === 'connect') {
            try {
                $result = call_user_func_array($func, $args);
            } catch (\ErrorException $e) {
                exit($e->getMessage().PHP_EOL);
            }

            if (!is_resource($this->resource)) {
                exit('An error occured while trying to connect to EPP server.'.PHP_EOL);
            }

            $result = null;
        } elseif (!is_resource($this->resource)) {
            exit('Not connected to EPP server.'.PHP_EOL);
        } else {
            array_unshift($args, $this->resource);
            try {
                $result = call_user_func_array($func, $args);
            } catch (\ErrorException $e) {
                exit($e->getMessage().PHP_EOL);
            }
        }

        return $result;
    }

    /**
     * login
     */
    public function login($params = array())
    {
        $return = array();
        try {
            $from = $to = array();
            $from[] = '/{{ clID }}/';
            $to[] = htmlspecialchars($params['clID']);
            $from[] = '/{{ pwd }}/';
            $to[] = htmlspecialchars($params['pw']);    
            if (isset($params['newpw']) && !empty($params['newpw'])) {
            $from[] = '/{{ newpw }}/';
            $to[] = PHP_EOL . '      <newPW>' . htmlspecialchars($params['newpw']) . '</newPW>';
            } else {
            $from[] = '/{{ newpw }}/';
            $to[] = '';
            }
            $from[] = '/{{ clTRID }}/';
            $microtime = str_replace('.', '', round(microtime(1), 3));
            $to[] = htmlspecialchars($params['prefix'] . '-login-' . $microtime);
            $xml = preg_replace($from, $to, '<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xsi:schemaLocation="urn:ietf:params:xml:ns:epp-1.0 epp-1.0.xsd">
  <command>
    <login>
      <clID>{{ clID }}</clID>
      <pw>{{ pwd }}</pw>{{ newpw }}
      <options>
        <version>1.0</version>
        <lang>en</lang>
      </options>
      <svcs>
        <objURI>urn:ietf:params:xml:ns:domain-1.0</objURI>
        <objURI>urn:ietf:params:xml:ns:contact-1.0</objURI>
        <objURI>urn:ietf:params:xml:ns:host-1.0</objURI>
        <objURI>http://www.verisign.com/epp/registry-1.0</objURI>
        <objURI>http://www.verisign.com/epp/lowbalance-poll-1.0</objURI>
        <objURI>http://www.verisign.com/epp/rgp-poll-1.0</objURI>
        <svcExtension>
          <extURI>urn:ietf:params:xml:ns:secDNS-1.1</extURI>
          <extURI>urn:ietf:params:xml:ns:epp:loginSec-1.0</extURI>
          <extURI>http://www.verisign.com/epp/whoisInf-1.0</extURI>
          <extURI>http://www.verisign.com/epp/idnLang-1.0</extURI>
          <extURI>urn:ietf:params:xml:ns:coa-1.0</extURI>
          <extURI>http://www.verisign-grs.com/epp/namestoreExt-1.1</extURI>
          <extURI>http://www.verisign.com/epp/sync-1.0</extURI>
          <extURI>http://www.verisign.com/epp/relatedDomain-1.0</extURI>
          <extURI>urn:ietf:params:xml:ns:verificationCode-1.0</extURI>
          <extURI>urn:ietf:params:xml:ns:rgp-1.0</extURI>
          <extURI>urn:ietf:params:xml:ns:changePoll-1.0</extURI>
        </svcExtension>
      </svcs>
    </login>
    <clTRID>{{ clTRID }}</clTRID>
  </command>
</epp>');
            $r = $this->writeRequest($xml);
            $code = (int)$r->response->result->attributes()->code;
            if ($code == 1000) {
                $this->isLoggedIn = true;
                $this->prefix = $params['prefix'];
            }

            $return = array(
                'code' => $code,
                'msg' => $r->response->result->msg
            );
        } catch (\Exception $e) {
            $return = array(
                'error' => $e->getMessage()
            );
        }

        return $return;
    }

    /**
     * logout
     */
    public function logout($params = array())
    {
        if (!$this->isLoggedIn) {
            return array(
                'code' => 2002,
                'msg' => 'Command use error'
            );
        }

        $return = array();
        try {
            $from = $to = array();
            $from[] = '/{{ clTRID }}/';
            $microtime = str_replace('.', '', round(microtime(1), 3));
            $to[] = htmlspecialchars($this->prefix . '-logout-' . $microtime);
            $xml = preg_replace($from, $to, '<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xsi:schemaLocation="urn:ietf:params:xml:ns:epp-1.0 epp-1.0.xsd">
  <command>
    <logout/>
    <clTRID>{{ clTRID }}</clTRID>
  </command>
</epp>');
            $r = $this->writeRequest($xml);
            $code = (int)$r->response->result->attributes()->code;
            if ($code == 1500) {
                $this->isLoggedIn = false;
            }

            $return = array(
                'code' => $code,
                'msg' => $r->response->result->msg
            );
        } catch (\Exception $e) {
            $return = array(
                'error' => $e->getMessage()
            );
        }

        return $return;
    }

    /**
     * domainInfo
     */
    public function domainInfo($params = array())
    {
        if (!$this->isLoggedIn) {
            return array(
                'code' => 2002,
                'msg' => 'Command use error'
            );
        }

        $return = array();
        try {
            $from = $to = array();
            $from[] = '/{{ domainname }}/';
            $to[] = htmlspecialchars($params['domainname']);
            $from[] = '/{{ authInfo }}/';
            $authInfo = (isset($params['authInfoPw']) ? "<domain:authInfo>\n<domain:pw><![CDATA[{$params['authInfoPw']}]]></domain:pw>\n</domain:authInfo>" : '');
            $to[] = $authInfo;
            $from[] = '/{{ clTRID }}/';
            $microtime = str_replace('.', '', round(microtime(1), 3));
            $to[] = htmlspecialchars($this->prefix . '-domain-info-' . $microtime);
            $from[] = "/<\w+:\w+>\s*<\/\w+:\w+>\s+/ims";
            $to[] = '';
            $xml = preg_replace($from, $to, '<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xsi:schemaLocation="urn:ietf:params:xml:ns:epp-1.0 epp-1.0.xsd">
  <command>
    <info>
      <domain:info
       xmlns:domain="urn:ietf:params:xml:ns:domain-1.0"
       xsi:schemaLocation="urn:ietf:params:xml:ns:domain-1.0 domain-1.0.xsd">
        <domain:name hosts="all">{{ domainname }}</domain:name>
        {{ authInfo }}
      </domain:info>
    </info>
    <extension>
      <namestoreExt:namestoreExt xmlns:namestoreExt="http://www.verisign-grs.com/epp/namestoreExt-1.1">
        <namestoreExt:subProduct>dotCOM</namestoreExt:subProduct>
      </namestoreExt:namestoreExt>
    </extension>
    <clTRID>{{ clTRID }}</clTRID>
  </command>
</epp>');
            $r = $this->writeRequest($xml);
            $code = (int)$r->response->result->attributes()->code;
            $msg = (string)$r->response->result->msg;
            $r = $r->response->resData->children('urn:ietf:params:xml:ns:domain-1.0')->infData;
            $name = (string)$r->name;
            $roid = (string)$r->roid;
            $status = array();
            $i = 0;
            foreach ($r->status as $e) {
                $i++;
                $status[$i] = (string)$e->attributes()->s;
            }
            $registrant = (string)$r->registrant;
            $contact = array();
            $i = 0;
            foreach ($r->contact as $e) {
                $i++;
                $contact[$i]['type'] = (string)$e->attributes()->type;
                $contact[$i]['id'] = (string)$e;
            }
            $ns = array();
            $i = 0;
            if (isset($r->ns->hostObj) && (is_array($r->ns->hostObj) || is_object($r->ns->hostObj))) {
                foreach ($r->ns->hostObj as $hostObj) {
                    $i++;
                    $ns[$i] = (string)$hostObj;
                }
            } else {
                $ns = [];
            }
            $host = array();
            $i = 0;
            foreach ($r->host as $hostname) {
                $i++;
                $host[$i] = (string)$hostname;
            }
            $clID = (string)$r->clID;
            $crID = (string)$r->crID;
            $crDate = (string)$r->crDate;
            $upID = (string)$r->upID;
            $upDate = (string)$r->upDate;
            $exDate = (string)$r->exDate;
            $trDate = (string)$r->trDate;
            $authInfo = (string)$r->authInfo->pw;

            $return = array(
                'code' => $code,
                'msg' => $msg,
                'name' => $name,
                'roid' => $roid,
                'status' => $status,
                'registrant' => $registrant,
                'contact' => $contact,
                'ns' => $ns,
                'host' => $host,
                'clID' => $clID,
                'crID' => $crID,
                'crDate' => $crDate,
                'upID' => $upID,
                'upDate' => $upDate,
                'exDate' => $exDate,
                'trDate' => $trDate,
                'authInfo' => $authInfo
            );
        } catch (\Exception $e) {
            $return = array(
                'error' => $e->getMessage()
            );
        }

        return $return;
    }

    public function _response_log($content)
    {
        $handle = fopen(dirname(__FILE__) . '/data/log/verisign_response.log', 'a');
        ob_start();
        echo "\n==================================\n";
        ob_end_clean();
        fwrite($handle, $content);
        fclose($handle);
    }

    public function _request_log($content)
    {
        $handle = fopen(dirname(__FILE__) . '/data/log/verisign_request.log', 'a');
        ob_start();
        echo "\n==================================\n";
        ob_end_clean();
        fwrite($handle, $content);
        fclose($handle);
    }
}