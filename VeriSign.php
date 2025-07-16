<?php
/**
 * EPP VeriSign Registrar Module for FOSSBilling (https://fossbilling.org/)
 *
 * Developed in 2024 by the Namingo Team (https://namingo.org, help@namingo.org)
 *
 * This project is based on:
 * - The "Generic EPP with DNSsec Registrar Module for WHMCS," originally developed in 2019 by Lilian Rudenco (info@xpanel.com)
 *   and licensed under the Academic Free License (AFL 3.0) - http://opensource.org/licenses/afl-3.0.php
 *
 * @license MIT
 */

use Symfony\Contracts\HttpClient\Exception\HttpExceptionInterface;

class Registrar_Adapter_VeriSign extends Registrar_AdapterAbstract
{
    public $config = array();
    public $socket;
    public $isLogined;

    public function __construct($options)
    {
        if(isset($options['username'])) {
            $this->config['username'] = $options['username'];
        }
        if(isset($options['password'])) {
            $this->config['password'] = $options['password'];
        }
        if(isset($options['host'])) {
            $this->config['host'] = $options['host'];
        }
        if(isset($options['port'])) {
            $this->config['port'] = $options['port'];
        }
        if(isset($options['registrarprefix'])) {
            $this->config['registrarprefix'] = $options['registrarprefix'];
        }
        if(isset($options['ssl_cert'])) {
            $this->config['ssl_cert'] = $options['ssl_cert'];
        }
        if(isset($options['ssl_key'])) {
            $this->config['ssl_key'] = $options['ssl_key'];
        }
        if(isset($options['ssl_ca'])) {
            $this->config['ssl_ca'] = $options['ssl_ca'];
        }
        if(isset($options['use_tls_12'])) {
            $this->config['use_tls_12'] = (bool)$options['use_tls_12'];
        } else {
            $this->config['use_tls_12'] = false;
        }
    }

    public function getTlds()
    {
        return array();
    }
    
    public static function getConfig()
    {
        return array(
            'label' => 'An EPP registry module allows registrars to manage and register domain names using the Extensible Provisioning Protocol (EPP). All details below are typically provided by the domain registry and are used to authenticate your account when connecting to the EPP server.',
            'form'  => array(
                'username' => array('text', array(
                    'label' => 'EPP Server Username',
                    'required' => true,
                ),
                ),
                'password' => array('password', array(
                    'label' => 'EPP Server Password',
                    'required' => true,
                    'renderPassword' => true,
                ),
                ),
                'host' => array('text', array(
                    'label' => 'EPP Server Host',
                    'required' => true,
                ),
                ),
                'port' => array('text', array(
                    'label' => 'EPP Server Port',
                    'required' => true,
                ),
                ),
                'registrarprefix' => array('text', array(
                    'label' => 'Registrar Prefix',
                    'required' => true,
                ),
                ),
                'ssl_cert' => array('text', array(
                    'label' => 'SSL Certificate Path',
                    'required' => true,
                ),
                ),
                'ssl_key' => array('text', array(
                    'label' => 'SSL Key Path',
                    'required' => true,
                ),
                ),
                'ssl_ca' => array('text', array(
                    'label' => 'SSL CA Path',
                    'required' => false,
                ),
                ),
                'use_tls_12' => array('radio', array(
                    'multiOptions' => array('1'=>'Yes', '0'=>'No'),
                    'label' => 'Use TLS 1.2 instead of 1.3',
                ),
                ),
            ),
        );
    }
    
    public function isDomaincanBeTransferred(Registrar_Domain $domain)
    {
        $this->getLog()->debug('Checking if domain can be transferred: ' . $domain->getName());
        return true;
    }

    public function isDomainAvailable(Registrar_Domain $domain)
    {
        $this->getLog()->debug('Checking domain availability: ' . $domain->getName());
        $s    = $this->connect();
        $this->login();
        $from = $to = array();
        $from[] = '/{{ name }}/';
        $to[] = htmlspecialchars($domain->getName());
        $tld = strtoupper(str_replace('.', '', $domain->getTld()));
        $from[] = '/{{ tld }}/';
        $to[]   = $tld;
        $from[] = '/{{ clTRID }}/';
        $clTRID = str_replace('.', '', round(microtime(1) , 3));
        $to[] = htmlspecialchars($this->config['registrarprefix'] . '-domain-check-' . $clTRID);
        $xml = preg_replace($from, $to, '<?xml version="1.0" encoding="UTF-8" standalone="no"?>
        <epp xmlns="urn:ietf:params:xml:ns:epp-1.0"
          xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
          xsi:schemaLocation="urn:ietf:params:xml:ns:epp-1.0 epp-1.0.xsd">
          <command>
            <check>
              <domain:check
                xmlns:domain="urn:ietf:params:xml:ns:domain-1.0"
                xsi:schemaLocation="urn:ietf:params:xml:ns:domain-1.0 domain-1.0.xsd">
                <domain:name>{{ name }}</domain:name>
              </domain:check>
            </check>
            <extension>
              <namestoreExt:namestoreExt xmlns:namestoreExt="http://www.verisign-grs.com/epp/namestoreExt-1.1">
                <namestoreExt:subProduct>dot{{ tld }}</namestoreExt:subProduct>
              </namestoreExt:namestoreExt>
            </extension>
            <clTRID>{{ clTRID }}</clTRID>
          </command>
        </epp>');

        $r = $this->write($xml, __FUNCTION__);
        $r = $r->response->resData->children('urn:ietf:params:xml:ns:domain-1.0')->chkData;
        $reason = (string)$r->cd[0]->reason;

        if ($reason)
        {
            return false;
        } else {
            return true;
        }
        if (!empty($s))
        {
            $this->logout();
        }

        return true;
    }

    public function modifyNs(Registrar_Domain $domain)
    {
        $this->getLog()->debug('Modifying nameservers: ' . $domain->getName());
        $this->getLog()->debug('Ns1: ' . $domain->getNs1());
        $this->getLog()->debug('Ns2: ' . $domain->getNs2());
        $this->getLog()->debug('Ns3: ' . $domain->getNs3());
        $this->getLog()->debug('Ns4: ' . $domain->getNs4());
        $return = array();
        try {
            $s    = $this->connect();
            $this->login();
            $from = $to = array();
            $from[] = '/{{ name }}/';
            $to[] = htmlspecialchars($domain->getName());
            $tld = strtoupper(str_replace('.', '', $domain->getTld()));
            $from[] = '/{{ tld }}/';
            $to[]   = $tld;
            $from[] = '/{{ clTRID }}/';
            $clTRID = str_replace('.', '', round(microtime(1), 3));
            $to[] = htmlspecialchars($this->config['registrarprefix'] . '-domain-info-' . $clTRID);
            $xml = preg_replace($from, $to, '<?xml version="1.0" encoding="UTF-8" standalone="no"?>
    <epp xmlns="urn:ietf:params:xml:ns:epp-1.0"
      xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
      xsi:schemaLocation="urn:ietf:params:xml:ns:epp-1.0 epp-1.0.xsd">
      <command>
        <info>
          <domain:info
           xmlns:domain="urn:ietf:params:xml:ns:domain-1.0"
           xsi:schemaLocation="urn:ietf:params:xml:ns:domain-1.0 domain-1.0.xsd">
            <domain:name hosts="all">{{ name }}</domain:name>
          </domain:info>
        </info>
        <extension>
          <namestoreExt:namestoreExt xmlns:namestoreExt="http://www.verisign-grs.com/epp/namestoreExt-1.1">
            <namestoreExt:subProduct>dot{{ tld }}</namestoreExt:subProduct>
          </namestoreExt:namestoreExt>
        </extension>
        <clTRID>{{ clTRID }}</clTRID>
      </command>
    </epp>');
            $r = $this->write($xml, __FUNCTION__);
            $r = $r->response->resData->children('urn:ietf:params:xml:ns:domain-1.0')->infData;
            $add = $rem = array();
            $i = 0;
            foreach($r->ns->hostObj as $ns) {
                $i++;
                $ns = (string)$ns;
                if (!$ns) {
                    continue;
                }

                $rem["ns{$i}"] = $ns;
            }

            foreach (range(1, 4) as $i) {
              $k = "getNs$i";
              $v = $domain->{$k}();
              if (!$v) {
                continue;
              }

              if ($k0 = array_search($v, $rem)) {
                unset($rem[$k0]);
              } else {
                $add["ns$i"] = $v;
              }
            }

            if (!empty($add) || !empty($rem)) {
                $from = $to = array();
                $text = '';
                foreach($add as $k => $v) {
                    $text.= '<domain:hostObj>' . $v . '</domain:hostObj>' . "\n";
                }

                $from[] = '/{{ add }}/';
                $to[] = (empty($text) ? '' : "<domain:add><domain:ns>\n{$text}</domain:ns></domain:add>\n");
                $text = '';
                foreach($rem as $k => $v) {
                    $text.= '<domain:hostObj>' . $v . '</domain:hostObj>' . "\n";
                }

                $from[] = '/{{ rem }}/';
                $to[] = (empty($text) ? '' : "<domain:rem><domain:ns>\n{$text}</domain:ns></domain:rem>\n");
                $from[] = '/{{ name }}/';
                $to[] = htmlspecialchars($domain->getName());
                $tld = strtoupper(str_replace('.', '', $domain->getTld()));
                $from[] = '/{{ tld }}/';
                $to[]   = $tld;
                $from[] = '/{{ clTRID }}/';
                $clTRID = str_replace('.', '', round(microtime(1), 3));
                $to[] = htmlspecialchars($this->config['registrarprefix'] . '-domain-update-' . $clTRID);
                $xml = preg_replace($from, $to, '<?xml version="1.0" encoding="UTF-8" standalone="no"?>
    <epp xmlns="urn:ietf:params:xml:ns:epp-1.0"
      xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
      xsi:schemaLocation="urn:ietf:params:xml:ns:epp-1.0 epp-1.0.xsd">
      <command>
        <update>
          <domain:update
           xmlns:domain="urn:ietf:params:xml:ns:domain-1.0"
           xsi:schemaLocation="urn:ietf:params:xml:ns:domain-1.0 domain-1.0.xsd">
            <domain:name>{{ name }}</domain:name>
        {{ add }}
        {{ rem }}
          </domain:update>
        </update>
        <extension>
          <namestoreExt:namestoreExt xmlns:namestoreExt="http://www.verisign-grs.com/epp/namestoreExt-1.1">
            <namestoreExt:subProduct>dot{{ tld }}</namestoreExt:subProduct>
          </namestoreExt:namestoreExt>
        </extension>
        <clTRID>{{ clTRID }}</clTRID>
      </command>
    </epp>');
                $r = $this->write($xml, __FUNCTION__);
            }
        }

        catch(exception $e) {
            $return = array(
                'error' => $e->getMessage()
            );
            throw new Registrar_Exception('Error: ' . $e->getMessage());
        }

        if (!empty($s)) {
            $this->logout();
        }

        return $return;
    }

    public function transferDomain(Registrar_Domain $domain)
    {
        $this->getLog()->debug('Transfering domain: ' . $domain->getName());
        $this->getLog()->debug('Epp code: ' . $domain->getEpp());
        $return = array();
        try {
            $s    = $this->connect();
            $this->login();
            $from = $to = array();
            $from[] = '/{{ name }}/';
            $to[] = htmlspecialchars($domain->getName());
            $from[] = '/{{ authInfo_pw }}/';
            $to[] = htmlspecialchars($domain->getEpp());
            $tld = strtoupper(str_replace('.', '', $domain->getTld()));
            $from[] = '/{{ tld }}/';
            $to[]   = $tld;
            $from[] = '/{{ clTRID }}/';
            $clTRID = str_replace('.', '', round(microtime(1), 3));
            $to[] = htmlspecialchars($this->config['registrarprefix'] . '-domain-transfer-' . $clTRID);
            $xml = preg_replace($from, $to, '<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xsi:schemaLocation="urn:ietf:params:xml:ns:epp-1.0 epp-1.0.xsd">
  <command>
    <transfer op="request">
      <domain:transfer
       xmlns:domain="urn:ietf:params:xml:ns:domain-1.0">
        <domain:name>{{ name }}</domain:name>
        <domain:period unit="y">1</domain:period>
        <domain:authInfo>
          <domain:pw>{{ authInfo_pw }}</domain:pw>
        </domain:authInfo>
      </domain:transfer>
    </transfer>
    <extension>
      <namestoreExt:namestoreExt xmlns:namestoreExt="http://www.verisign-grs.com/epp/namestoreExt-1.1">
        <namestoreExt:subProduct>dot{{ tld }}</namestoreExt:subProduct>
      </namestoreExt:namestoreExt>
    </extension>
    <clTRID>{{ clTRID }}</clTRID>
  </command>
</epp>');
            $r = $this->write($xml, __FUNCTION__);
            $r = $r->response->resData->children('urn:ietf:params:xml:ns:domain-1.0')->trnData;
        }

        catch(exception $e) {
            $return = array(
                'error' => $e->getMessage()
            );
        }

        if (!empty($s)) {
            $this->logout();
        }

        return $return;
    }

    public function getDomainDetails(Registrar_Domain $domain)
    {
        $this->getLog()->debug('Getting domain details: ' . $domain->getName());
        try {
            $s    = $this->connect();
            $this->login();
            $from = $to = array();
            $from[] = '/{{ name }}/';
            $to[] = htmlspecialchars($domain->getName());
            $tld = strtoupper(str_replace('.', '', $domain->getTld()));
            $from[] = '/{{ tld }}/';
            $to[]   = $tld;
            $from[] = '/{{ clTRID }}/';
            $clTRID = str_replace('.', '', round(microtime(1), 3));
            $to[] = htmlspecialchars($this->config['registrarprefix'] . '-domain-info-' . $clTRID);
            $xml = preg_replace($from, $to, '<?xml version="1.0" encoding="UTF-8" standalone="no"?>
    <epp xmlns="urn:ietf:params:xml:ns:epp-1.0"
      xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
      xsi:schemaLocation="urn:ietf:params:xml:ns:epp-1.0 epp-1.0.xsd">
      <command>
        <info>
          <domain:info
           xmlns:domain="urn:ietf:params:xml:ns:domain-1.0"
           xsi:schemaLocation="urn:ietf:params:xml:ns:domain-1.0 domain-1.0.xsd">
            <domain:name hosts="all">{{ name }}</domain:name>
          </domain:info>
        </info>
        <extension>
          <namestoreExt:namestoreExt xmlns:namestoreExt="http://www.verisign-grs.com/epp/namestoreExt-1.1">
            <namestoreExt:subProduct>dot{{ tld }}</namestoreExt:subProduct>
          </namestoreExt:namestoreExt>
        </extension>
        <clTRID>{{ clTRID }}</clTRID>
      </command>
    </epp>');
            $r = $this->write($xml, __FUNCTION__);
            $r = $r->response->resData->children('urn:ietf:params:xml:ns:domain-1.0')->infData;
            $crDate = (string)$r->crDate;
            $exDate = (string)$r->exDate;
            $eppcode = (string)$r->authInfo->pw;

            $status = array();
            $i = 0;
            foreach ($r->status as $e) {
                $i++;
                $status[$i] = (string)$e->attributes()->s;
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

            $crDate = strtotime($crDate);
            $exDate = strtotime($exDate);

            $domain->setRegistrationTime($crDate);
            $domain->setExpirationTime($exDate);
            $domain->setEpp($eppcode);

            $domain->setNs1(isset($ns[0]) ? $ns[0] : '');
            $domain->setNs2(isset($ns[1]) ? $ns[1] : '');
            $domain->setNs3(isset($ns[2]) ? $ns[2] : '');
            $domain->setNs4(isset($ns[3]) ? $ns[3] : '');
        }

        catch(exception $e) {
            throw new Registrar_Exception('Error: ' . $e->getMessage());
        }

        if (!empty($s)) {
            $this->logout();
        }

        return $domain;
    }

    public function deleteDomain(Registrar_Domain $domain)
    {
        $this->getLog()->debug('Removing domain: ' . $domain->getName());
        $return = array();
        try {
            $s    = $this->connect();
            $this->login();
            $from = $to = array();
            $from[] = '/{{ name }}/';
            $to[] = htmlspecialchars($domain->getName());
            $tld = strtoupper(str_replace('.', '', $domain->getTld()));
            $from[] = '/{{ tld }}/';
            $to[]   = $tld;
            $from[] = '/{{ clTRID }}/';
            $clTRID = str_replace('.', '', round(microtime(1), 3));
            $to[] = htmlspecialchars($this->config['registrarprefix'] . '-domain-delete-' . $clTRID);
            $xml = preg_replace($from, $to, '<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xsi:schemaLocation="urn:ietf:params:xml:ns:epp-1.0 epp-1.0.xsd">
  <command>
    <delete>
      <domain:delete
       xmlns:domain="urn:ietf:params:xml:ns:domain-1.0">
        <domain:name>{{ name }}</domain:name>
      </domain:delete>
    </delete>
    <extension>
      <namestoreExt:namestoreExt xmlns:namestoreExt="http://www.verisign-grs.com/epp/namestoreExt-1.1">
        <namestoreExt:subProduct>dot{{ tld }}</namestoreExt:subProduct>
      </namestoreExt:namestoreExt>
    </extension>
    <clTRID>{{ clTRID }}</clTRID>
  </command>
</epp>');
            $r = $this->write($xml, __FUNCTION__);
        }

        catch(exception $e) {
            $return = array(
                'error' => $e->getMessage()
            );
        }

        if (!empty($s)) {
            $this->logout();
        }

        return $return;
    }

    public function registerDomain(Registrar_Domain $domain)
    {
        $this->getLog()->debug('Registering domain: ' . $domain->getName(). ' for '.$domain->getRegistrationPeriod(). ' years');
        $client = $domain->getContactRegistrar();

        $return = array();
        try {
            $s = $this->connect();
            $this->login();
            $from = $to = array();
            $from[] = '/{{ name }}/';
            $to[] = htmlspecialchars($domain->getName());
            $tld = strtoupper(str_replace('.', '', $domain->getTld()));
            $from[] = '/{{ tld }}/';
            $to[]   = $tld;
            $from[] = '/{{ clTRID }}/';
            $clTRID = str_replace('.', '', round(microtime(1), 3));
            $to[] = htmlspecialchars($this->config['registrarprefix'] . '-domain-check-' . $clTRID);
            $xml = preg_replace($from, $to, '<?xml version="1.0" encoding="UTF-8" standalone="no"?>
    <epp xmlns="urn:ietf:params:xml:ns:epp-1.0"
      xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
      xsi:schemaLocation="urn:ietf:params:xml:ns:epp-1.0 epp-1.0.xsd">
      <command>
        <check>
          <domain:check
            xmlns:domain="urn:ietf:params:xml:ns:domain-1.0"
            xsi:schemaLocation="urn:ietf:params:xml:ns:domain-1.0 domain-1.0.xsd">
            <domain:name>{{ name }}</domain:name>
          </domain:check>
        </check>
        <extension>
          <namestoreExt:namestoreExt xmlns:namestoreExt="http://www.verisign-grs.com/epp/namestoreExt-1.1">
            <namestoreExt:subProduct>dot{{ tld }}</namestoreExt:subProduct>
          </namestoreExt:namestoreExt>
        </extension>
        <clTRID>{{ clTRID }}</clTRID>
      </command>
    </epp>');
            $r = $this->write($xml, __FUNCTION__);
            $r = $r->response->resData->children('urn:ietf:params:xml:ns:domain-1.0')->chkData;
            $reason = (string)$r->cd[0]->reason;
            if (!$reason) {
                $reason = 'Domain is not available';
            }

            if (0 == (int)$r->cd[0]->name->attributes()->avail) {
                throw new Registrar_Exception($r->cd[0]->name . ' ' . $reason);
            }
            
            //host create
            foreach (['ns1', 'ns2', 'ns3', 'ns4'] as $ns) {
                if ($domain->{'get' . ucfirst($ns)}()) {
                    $from = $to = array();
                    $from[] = '/{{ name }}/';
                    $to[] = $domain->{'get' . ucfirst($ns)}();
                    $tld = strtoupper(str_replace('.', '', $domain->getTld()));
                    $from[] = '/{{ tld }}/';
                    $to[]   = $tld;
                    $from[] = '/{{ clTRID }}/';
                    $clTRID = str_replace('.', '', round(microtime(1), 3));
                    $to[] = htmlspecialchars($this->config['registrarprefix'] . '-host-check-' . $clTRID);
                    $xml = preg_replace($from, $to, '<?xml version="1.0" encoding="UTF-8" standalone="no"?>
                    <epp xmlns="urn:ietf:params:xml:ns:epp-1.0"
                      xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
                      xsi:schemaLocation="urn:ietf:params:xml:ns:epp-1.0 epp-1.0.xsd">
                      <command>
                        <check>
                          <host:check
                            xmlns:host="urn:ietf:params:xml:ns:host-1.0"
                            xsi:schemaLocation="urn:ietf:params:xml:ns:host-1.0 host-1.0.xsd">
                            <host:name>{{ name }}</host:name>
                          </host:check>
                        </check>
                        <extension>
                          <namestoreExt:namestoreExt xmlns:namestoreExt="http://www.verisign-grs.com/epp/namestoreExt-1.1">
                            <namestoreExt:subProduct>dot{{ tld }}</namestoreExt:subProduct>
                          </namestoreExt:namestoreExt>
                        </extension>
                        <clTRID>{{ clTRID }}</clTRID>
                      </command>
                    </epp>');
                    $r = $this->write($xml, __FUNCTION__);
                    $r = $r->response->resData->children('urn:ietf:params:xml:ns:host-1.0')->chkData;

                    if (0 == (int)$r->cd[0]->name->attributes()->avail) {
                        continue;
                    }

                    $from = $to = array();
                    $from[] = '/{{ name }}/';
                    $to[] = $domain->{'get' . ucfirst($ns)}();
                    $tld = strtoupper(str_replace('.', '', $domain->getTld()));
                    $from[] = '/{{ tld }}/';
                    $to[]   = $tld;
                    $from[] = '/{{ clTRID }}/';
                    $clTRID = str_replace('.', '', round(microtime(1), 3));
                    $to[] = htmlspecialchars($this->config['registrarprefix'] . '-host-create-' . $clTRID);
                    $xml = preg_replace($from, $to, '<?xml version="1.0" encoding="UTF-8" standalone="no"?>
                    <epp xmlns="urn:ietf:params:xml:ns:epp-1.0"
                      xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
                      xsi:schemaLocation="urn:ietf:params:xml:ns:epp-1.0 epp-1.0.xsd">
                      <command>
                        <create>
                          <host:create
                           xmlns:host="urn:ietf:params:xml:ns:host-1.0">
                            <host:name>{{ name }}</host:name>
                          </host:create>
                          <extension>
                            <namestoreExt:namestoreExt xmlns:namestoreExt="http://www.verisign-grs.com/epp/namestoreExt-1.1">
                              <namestoreExt:subProduct>dot{{ tld }}</namestoreExt:subProduct>
                            </namestoreExt:namestoreExt>
                          </extension>
                        <clTRID>{{ clTRID }}</clTRID>
                      </command>
                    </epp>');
                    $r = $this->write($xml, __FUNCTION__);
                }
            }

            $from = $to = array();
            $from[] = '/{{ name }}/';
            $to[] = htmlspecialchars($domain->getName());
            $from[] = '/{{ period }}/';
            $to[] = htmlspecialchars($domain->getRegistrationPeriod());
            if($domain->getNs1()) {
            $from[] = '/{{ ns1 }}/';
            $to[] = htmlspecialchars($domain->getNs1());
            } else {
            $from[] = '/{{ ns1 }}/';
            $to[] = '';
            }
            if($domain->getNs2()) {
            $from[] = '/{{ ns2 }}/';
            $to[] = htmlspecialchars($domain->getNs2());
            } else {
            $from[] = '/{{ ns2 }}/';
            $to[] = '';
            }
            if($domain->getNs3()) {
            $from[] = '/{{ ns3 }}/';
            $to[] = htmlspecialchars($domain->getNs3());
            } else {
            $from[] = '/{{ ns3 }}/';
            $to[] = '';
            }
            if($domain->getNs4()) {
            $from[] = '/{{ ns4 }}/';
            $to[] = htmlspecialchars($domain->getNs4());
            } else {
            $from[] = '/{{ ns4 }}/';
            $to[] = '';
            }
            $from[] = '/{{ authInfo }}/';
            $to[] = htmlspecialchars($this->generateObjectPW());
            $tld = strtoupper(str_replace('.', '', $domain->getTld()));
            $from[] = '/{{ tld }}/';
            $to[]   = $tld;
            $from[] = '/{{ clTRID }}/';
            $clTRID = str_replace('.', '', round(microtime(1), 3));
            $to[] = htmlspecialchars($this->config['registrarprefix'] . '-domain-create-' . $clTRID);
            $from[] = "/<\w+:\w+>\s*<\/\w+:\w+>\s+/ims";
            $to[] = '';

            $xml = preg_replace($from, $to, '<?xml version="1.0" encoding="UTF-8" standalone="no"?>
            <epp xmlns="urn:ietf:params:xml:ns:epp-1.0"
              xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
              xsi:schemaLocation="urn:ietf:params:xml:ns:epp-1.0 epp-1.0.xsd">
              <command>
                <create>
                  <domain:create
                   xmlns:domain="urn:ietf:params:xml:ns:domain-1.0">
                    <domain:name>{{ name }}</domain:name>
                    <domain:period unit="y">{{ period }}</domain:period>
                    <domain:ns>
                      <domain:hostObj>{{ ns1 }}</domain:hostObj>
                      <domain:hostObj>{{ ns2 }}</domain:hostObj>
                      <domain:hostObj>{{ ns3 }}</domain:hostObj>
                      <domain:hostObj>{{ ns4 }}</domain:hostObj>
                    </domain:ns>
                    <domain:authInfo>
                      <domain:pw>{{ authInfo }}</domain:pw>
                    </domain:authInfo>
                  </domain:create>
                </create>
                <extension>
                  <namestoreExt:namestoreExt xmlns:namestoreExt="http://www.verisign-grs.com/epp/namestoreExt-1.1">
                    <namestoreExt:subProduct>dot{{ tld }}</namestoreExt:subProduct>
                  </namestoreExt:namestoreExt>
                </extension>
                <clTRID>{{ clTRID }}</clTRID>
              </command>
            </epp>');
            $r = $this->write($xml, __FUNCTION__);
        }

        catch(exception $e) {
            $return = array(
                'error' => $e->getMessage()
            );
            throw new Registrar_Exception('Error: ' . $e->getMessage());
        }

        if (!empty($s)) {
            $this->logout();
        }

        return $return;
    }

    public function renewDomain(Registrar_Domain $domain)
    {
        $this->getLog()->debug('Renewing domain: ' . $domain->getName());
        $return = array();
        try {
            $s    = $this->connect();
            $this->login();
            $from = $to = array();
            $from[] = '/{{ name }}/';
            $to[] = htmlspecialchars($domain->getName());
            $tld = strtoupper(str_replace('.', '', $domain->getTld()));
            $from[] = '/{{ tld }}/';
            $to[]   = $tld;
            $from[] = '/{{ clTRID }}/';
            $clTRID = str_replace('.', '', round(microtime(1), 3));
            $to[] = htmlspecialchars($this->config['registrarprefix'] . '-domain-info-' . $clTRID);
            $xml = preg_replace($from, $to, '<?xml version="1.0" encoding="UTF-8" standalone="no"?>
    <epp xmlns="urn:ietf:params:xml:ns:epp-1.0"
      xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
      xsi:schemaLocation="urn:ietf:params:xml:ns:epp-1.0 epp-1.0.xsd">
      <command>
        <info>
          <domain:info
           xmlns:domain="urn:ietf:params:xml:ns:domain-1.0"
           xsi:schemaLocation="urn:ietf:params:xml:ns:domain-1.0 domain-1.0.xsd">
            <domain:name hosts="all">{{ name }}</domain:name>
          </domain:info>
        </info>
        <extension>
          <namestoreExt:namestoreExt xmlns:namestoreExt="http://www.verisign-grs.com/epp/namestoreExt-1.1">
            <namestoreExt:subProduct>dot{{ tld }}</namestoreExt:subProduct>
          </namestoreExt:namestoreExt>
        </extension>
        <clTRID>{{ clTRID }}</clTRID>
      </command>
    </epp>');
            $r = $this->write($xml, __FUNCTION__);
            $r = $r->response->resData->children('urn:ietf:params:xml:ns:domain-1.0')->infData;
            $expDate = (string)$r->exDate;
            $expDate = preg_replace("/^(\d+\-\d+\-\d+)\D.*$/", "$1", $expDate);
            $from = $to = array();
            $from[] = '/{{ name }}/';
            $to[] = htmlspecialchars($domain->getName());
            $from[] = '/{{ expDate }}/';
            $to[] = htmlspecialchars($expDate);
            $tld = strtoupper(str_replace('.', '', $domain->getTld()));
            $from[] = '/{{ tld }}/';
            $to[]   = $tld;
            $from[] = '/{{ clTRID }}/';
            $clTRID = str_replace('.', '', round(microtime(1), 3));
            $to[] = htmlspecialchars($this->config['registrarprefix'] . '-domain-renew-' . $clTRID);
            $xml = preg_replace($from, $to, '<?xml version="1.0" encoding="UTF-8" standalone="no"?>
    <epp xmlns="urn:ietf:params:xml:ns:epp-1.0"
      xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
      xsi:schemaLocation="urn:ietf:params:xml:ns:epp-1.0 epp-1.0.xsd">
      <command>
        <renew>
          <domain:renew
           xmlns:domain="urn:ietf:params:xml:ns:domain-1.0">
            <domain:name>{{ name }}</domain:name>
            <domain:curExpDate>{{ expDate }}</domain:curExpDate>
            <domain:period unit="y">1</domain:period>
          </domain:renew>
        </renew>
        <extension>
          <namestoreExt:namestoreExt xmlns:namestoreExt="http://www.verisign-grs.com/epp/namestoreExt-1.1">
            <namestoreExt:subProduct>dot{{ tld }}</namestoreExt:subProduct>
          </namestoreExt:namestoreExt>
        </extension>
        <clTRID>{{ clTRID }}</clTRID>
      </command>
    </epp>');
            $r = $this->write($xml, __FUNCTION__);
        }

        catch(exception $e) {
            $return = array(
                'error' => $e->getMessage()
            );
        }

        if (!empty($s)) {
            $this->logout();
        }

        return $return;
    }

    public function modifyContact(Registrar_Domain $domain)
    {
        $this->getLog()->debug('Updating contact info: ' . $domain->getName());

        throw new Registrar_Exception("Registry does not support contacts.");
    }
    
    public function enablePrivacyProtection(Registrar_Domain $domain)
    {
        $this->getLog()->debug('Enabling Privacy protection: ' . $domain->getName());

        throw new Registrar_Exception("Registry does not support contacts.");
    }
    
    public function disablePrivacyProtection(Registrar_Domain $domain)
    {
        $this->getLog()->debug('Disabling Privacy protection: ' . $domain->getName());

        throw new Registrar_Exception("Registry does not support contacts.");
    }

    public function getEpp(Registrar_Domain $domain)
    {
        $this->getLog()->debug('Retrieving domain transfer code: ' . $domain->getName());
        $return = array();
        try {
            $s    = $this->connect();
            $this->login();
            $from = $to = array();
            $from[] = '/{{ name }}/';
            $to[] = htmlspecialchars($domain->getName());
            $tld = strtoupper(str_replace('.', '', $domain->getTld()));
            $from[] = '/{{ tld }}/';
            $to[]   = $tld;
            $from[] = '/{{ clTRID }}/';
            $clTRID = str_replace('.', '', round(microtime(1), 3));
            $to[] = htmlspecialchars($this->config['registrarprefix'] . '-domain-info-' . $clTRID);
            $xml = preg_replace($from, $to, '<?xml version="1.0" encoding="UTF-8" standalone="no"?>
            <epp xmlns="urn:ietf:params:xml:ns:epp-1.0"
              xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
              xsi:schemaLocation="urn:ietf:params:xml:ns:epp-1.0 epp-1.0.xsd">
              <command>
                <info>
                  <domain:info
                   xmlns:domain="urn:ietf:params:xml:ns:domain-1.0"
                   xsi:schemaLocation="urn:ietf:params:xml:ns:domain-1.0 domain-1.0.xsd">
                    <domain:name hosts="all">{{ name }}</domain:name>
                  </domain:info>
                </info>
                <extension>
                  <namestoreExt:namestoreExt xmlns:namestoreExt="http://www.verisign-grs.com/epp/namestoreExt-1.1">
                    <namestoreExt:subProduct>dot{{ tld }}</namestoreExt:subProduct>
                  </namestoreExt:namestoreExt>
                </extension>
                <clTRID>{{ clTRID }}</clTRID>
              </command>
            </epp>');
            $r = $this->write($xml, __FUNCTION__);
            $r = $r->response->resData->children('urn:ietf:params:xml:ns:domain-1.0')->infData;
            $eppcode = (string)$r->authInfo->pw;

            if (!empty($s)) {
                    $this->logout();
                }
            return $eppcode;
        }

        catch(exception $e) {
            $return = array(
                'error' => $e->getMessage()
            );
        }

        if (!empty($s)) {
            $this->logout();
        }

        return $return;
    }

    public function lock(Registrar_Domain $domain)
    {
        $this->getLog()->debug('Locking domain: ' . $domain->getName());
        $return = array();
        try {
            $s    = $this->connect();
            $this->login();
            $from = $to = array();
            $from[] = '/{{ name }}/';
            $to[] = htmlspecialchars($domain->getName());
            $tld = strtoupper(str_replace('.', '', $domain->getTld()));
            $from[] = '/{{ tld }}/';
            $to[]   = $tld;
            $from[] = '/{{ clTRID }}/';
            $clTRID = str_replace('.', '', round(microtime(1), 3));
            $to[] = htmlspecialchars($this->config['registrarprefix'] . '-domain-info-' . $clTRID);
            $xml = preg_replace($from, $to, '<?xml version="1.0" encoding="UTF-8" standalone="no"?>
    <epp xmlns="urn:ietf:params:xml:ns:epp-1.0"
      xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
      xsi:schemaLocation="urn:ietf:params:xml:ns:epp-1.0 epp-1.0.xsd">
      <command>
        <info>
          <domain:info
           xmlns:domain="urn:ietf:params:xml:ns:domain-1.0"
           xsi:schemaLocation="urn:ietf:params:xml:ns:domain-1.0 domain-1.0.xsd">
            <domain:name hosts="all">{{ name }}</domain:name>
          </domain:info>
        </info>
        <extension>
          <namestoreExt:namestoreExt xmlns:namestoreExt="http://www.verisign-grs.com/epp/namestoreExt-1.1">
            <namestoreExt:subProduct>dot{{ tld }}</namestoreExt:subProduct>
          </namestoreExt:namestoreExt>
        </extension>
        <clTRID>{{ clTRID }}</clTRID>
      </command>
    </epp>');
            $r = $this->write($xml, __FUNCTION__);
            $r = $r->response->resData->children('urn:ietf:params:xml:ns:domain-1.0')->infData;
            $status = array();
            foreach($r->status as $e) {
                $st = (string)$e->attributes()->s;
                if (!preg_match("/^client.+Prohibited$/i", $st)) {
                    continue;
                }

                $status[$st] = true;
            }

            $add = array();
            foreach(array(
                'clientDeleteProhibited',
                'clientTransferProhibited'
            ) as $st) {
                if (!isset($status[$st])) {
                    $add[] = $st;
                }
            }

            if (!empty($add)) {
                $text = '';
                foreach($add as $st) {
                    $text.= '<domain:status s="' . $st . '" lang="en"></domain:status>' . "\n";
                }
                $from = $to = array();
                $from[] = '/{{ add }}/';
                $to[] = (empty($text) ? '' : "<domain:add>\n{$text}</domain:add>\n");
                $from[] = '/{{ name }}/';
                $to[] = htmlspecialchars($domain->getName());
                $tld = strtoupper(str_replace('.', '', $domain->getTld()));
                $from[] = '/{{ tld }}/';
                $to[]   = $tld;
                $from[] = '/{{ clTRID }}/';
                $clTRID = str_replace('.', '', round(microtime(1), 3));
                $to[] = htmlspecialchars($this->config['registrarprefix'] . '-domain-update-' . $clTRID);
                $xml = preg_replace($from, $to, '<?xml version="1.0" encoding="UTF-8" standalone="no"?>
    <epp xmlns="urn:ietf:params:xml:ns:epp-1.0"
      xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
      xsi:schemaLocation="urn:ietf:params:xml:ns:epp-1.0 epp-1.0.xsd">
      <command>
        <update>
          <domain:update
           xmlns:domain="urn:ietf:params:xml:ns:domain-1.0"
           xsi:schemaLocation="urn:ietf:params:xml:ns:domain-1.0 domain-1.0.xsd">
            <domain:name>{{ name }}</domain:name>
            {{ add }}
          </domain:update>
        </update>
        <extension>
          <namestoreExt:namestoreExt xmlns:namestoreExt="http://www.verisign-grs.com/epp/namestoreExt-1.1">
            <namestoreExt:subProduct>dot{{ tld }}</namestoreExt:subProduct>
          </namestoreExt:namestoreExt>
        </extension>
        <clTRID>{{ clTRID }}</clTRID>
      </command>
    </epp>');
                $r = $this->write($xml, __FUNCTION__);
            }
        }

        catch(exception $e) {
            $return = array(
                'error' => $e->getMessage()
            );
        }

        if (!empty($s)) {
            $this->logout();
        }

        return $return;
    }

    public function unlock(Registrar_Domain $domain)
    {
        $this->getLog()->debug('Unlocking: ' . $domain->getName());
        $return = array();
        try {
            $s    = $this->connect();
            $this->login();
            $from = $to = array();
            $from[] = '/{{ name }}/';
            $to[] = htmlspecialchars($domain->getName());
            $tld = strtoupper(str_replace('.', '', $domain->getTld()));
            $from[] = '/{{ tld }}/';
            $to[]   = $tld;
            $from[] = '/{{ clTRID }}/';
            $clTRID = str_replace('.', '', round(microtime(1), 3));
            $to[] = htmlspecialchars($this->config['registrarprefix'] . '-domain-info-' . $clTRID);
            $xml = preg_replace($from, $to, '<?xml version="1.0" encoding="UTF-8" standalone="no"?>
    <epp xmlns="urn:ietf:params:xml:ns:epp-1.0"
      xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
      xsi:schemaLocation="urn:ietf:params:xml:ns:epp-1.0 epp-1.0.xsd">
      <command>
        <info>
          <domain:info
           xmlns:domain="urn:ietf:params:xml:ns:domain-1.0"
           xsi:schemaLocation="urn:ietf:params:xml:ns:domain-1.0 domain-1.0.xsd">
            <domain:name hosts="all">{{ name }}</domain:name>
          </domain:info>
        </info>
        <extension>
          <namestoreExt:namestoreExt xmlns:namestoreExt="http://www.verisign-grs.com/epp/namestoreExt-1.1">
            <namestoreExt:subProduct>dot{{ tld }}</namestoreExt:subProduct>
          </namestoreExt:namestoreExt>
        </extension>
        <clTRID>{{ clTRID }}</clTRID>
      </command>
    </epp>');
            $r = $this->write($xml, __FUNCTION__);
            $r = $r->response->resData->children('urn:ietf:params:xml:ns:domain-1.0')->infData;
            $status = array();
            foreach($r->status as $e) {
                $st = (string)$e->attributes()->s;
                if (!preg_match("/^client.+Prohibited$/i", $st)) {
                    continue;
                }

                $status[$st] = true;
            }

            $rem = array();
            foreach(array(
                'clientDeleteProhibited',
                'clientTransferProhibited'
            ) as $st) {
                if (isset($status[$st])) {
                    $rem[] = $st;
                }
            }

            if (!empty($rem)) {
                $text = '';
                foreach($rem as $st) {
                    $text.= '<domain:status s="' . $st . '" lang="en"></domain:status>' . "\n";
                }
                $from = $to = array();
                $from[] = '/{{ rem }}/';
                $to[] = (empty($text) ? '' : "<domain:rem>\n{$text}</domain:rem>\n");
                $from[] = '/{{ name }}/';
                $to[] = htmlspecialchars($domain->getName());
                $tld = strtoupper(str_replace('.', '', $domain->getTld()));
                $from[] = '/{{ tld }}/';
                $to[]   = $tld;
                $from[] = '/{{ clTRID }}/';
                $clTRID = str_replace('.', '', round(microtime(1), 3));
                $to[] = htmlspecialchars($this->config['registrarprefix'] . '-domain-update-' . $clTRID);
                $xml = preg_replace($from, $to, '<?xml version="1.0" encoding="UTF-8" standalone="no"?>
    <epp xmlns="urn:ietf:params:xml:ns:epp-1.0"
      xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
      xsi:schemaLocation="urn:ietf:params:xml:ns:epp-1.0 epp-1.0.xsd">
      <command>
        <update>
          <domain:update
           xmlns:domain="urn:ietf:params:xml:ns:domain-1.0"
           xsi:schemaLocation="urn:ietf:params:xml:ns:domain-1.0 domain-1.0.xsd">
            <domain:name>{{ name }}</domain:name>
            {{ rem }}
          </domain:update>
        </update>
        <extension>
          <namestoreExt:namestoreExt xmlns:namestoreExt="http://www.verisign-grs.com/epp/namestoreExt-1.1">
            <namestoreExt:subProduct>dot{{ tld }}</namestoreExt:subProduct>
          </namestoreExt:namestoreExt>
        </extension>
        <clTRID>{{ clTRID }}</clTRID>
      </command>
    </epp>');
                $r = $this->write($xml, __FUNCTION__);
            }
        }

        catch(exception $e) {
            $return = array(
                'error' => $e->getMessage()
            );
        }

        if (!empty($s)) {
            $this->logout();
        }

        return $return;
    }

    public function connect()
    {
        $host = $this->config['host'];
        $port = $this->config['port'];
        $timeout = 30;
        
        $opts = array(
            'ssl' => array(
                'verify_peer' => false,
                'verify_peer_name' => false,
                'verify_host' => false,
                'allow_self_signed' => true,
                'local_cert' => $this->config['ssl_cert'],
                'local_pk' => $this->config['ssl_key']
            )
        );
        $context = stream_context_create($opts);
        if ($this->config['use_tls_12'] === true) {
            $tls = 'tlsv1.2';
        } else {
            $tls = 'tlsv1.3';
        }
        $this->socket = stream_socket_client($tls."://{$host}:{$port}", $errno, $errmsg, $timeout, STREAM_CLIENT_CONNECT, $context);

        if (!$this->socket) {
            throw new Registrar_Exception("Cannot connect to server '{$host}': {$errmsg}");
        }

        return $this->read();
    }

    public function login()
    {
        $from = $to = array();
        $from[] = '/{{ clID }}/';
        $to[] = htmlspecialchars($this->config['username']);
        $from[] = '/{{ pw }}/';
        $to[] = $this->config['password'];
        $from[] = '/{{ clTRID }}/';
        $clTRID = str_replace('.', '', round(microtime(1), 3));
        $to[] = htmlspecialchars($this->config['registrarprefix'] . '-login-' . $clTRID);
        $xml = preg_replace($from, $to, '<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xsi:schemaLocation="urn:ietf:params:xml:ns:epp-1.0 epp-1.0.xsd">
  <command>
    <login>
      <clID>{{ clID }}</clID>
      <pw><![CDATA[{{ pw }}]]></pw>
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
        $r = $this->write($xml, __FUNCTION__);
        $this->isLogined = true;
        return true;
    }

    public function logout()
    {
        if (!$this->isLogined) {
            return true;
        }

        $from = $to = array();
        $from[] = '/{{ clTRID }}/';
        $clTRID = str_replace('.', '', round(microtime(1), 3));
        $to[] = htmlspecialchars($this->config['registrarprefix'] . '-logout-' . $clTRID);
        $xml = preg_replace($from, $to, '<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<epp xmlns="urn:ietf:params:xml:ns:epp-1.0"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xsi:schemaLocation="urn:ietf:params:xml:ns:epp-1.0 epp-1.0.xsd">
  <command>
    <logout/>
    <clTRID>{{ clTRID }}</clTRID>
  </command>
</epp>');
        $r = $this->write($xml, __FUNCTION__);
        $this->isLogined = false;
        return true;
    }

    public function read()
    {
        $hdr = stream_get_contents($this->socket, 4);
        if ($hdr === false) {
            throw new Registrar_Exception('Connection appears to have closed.');
        }
        if (strlen($hdr) < 4) {
            throw new Registrar_Exception('Failed to read header from the connection.');
        }
        $unpacked = unpack('N', $hdr);
        $xml = fread($this->socket, ($unpacked[1] - 4));
        $xml = preg_replace('/></', ">\n<", $xml);      
        return $xml;
    }

    public function write($xml)
    {
        if (fwrite($this->socket, pack('N', (strlen($xml) + 4)) . $xml) === false) {
            throw new Registrar_Exception('Error writing to the connection.');
        }
        $xml_string = $this->read();
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
            throw new Registrar_Exception($r->response->result->msg);
        }
        return $r;
    }


    public function disconnect()
    {
        $result = fclose($this->socket);
        if (!$result) {
             throw new Registrar_Exception('Error closing the connection.');
        }
        $this->socket = null;
        return $result;
    }

    function generateObjectPW($objType = 'none')
    {
        $result = '';
        $uppercaseChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        $lowercaseChars = "abcdefghijklmnopqrstuvwxyz";
        $numbers = "1234567890";
        $specialSymbols = "!=+-";
        $minLength = 13;
        $maxLength = 13;
        $length = mt_rand($minLength, $maxLength);

        // Include at least one character from each set
        $result .= $uppercaseChars[mt_rand(0, strlen($uppercaseChars) - 1)];
        $result .= $lowercaseChars[mt_rand(0, strlen($lowercaseChars) - 1)];
        $result .= $numbers[mt_rand(0, strlen($numbers) - 1)];
        $result .= $specialSymbols[mt_rand(0, strlen($specialSymbols) - 1)];

        // Append random characters to reach the desired length
        while (strlen($result) < $length) {
            $chars = $uppercaseChars . $lowercaseChars . $numbers . $specialSymbols;
            $result .= $chars[mt_rand(0, strlen($chars) - 1)];
        }

        return 'aA1' . $result;
    }
    
    public function generateRandomString() 
    {
        $characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
        $randomString = '';
        for ($i = 0; $i < 12; $i++) {
            $randomString .= $characters[rand(0, strlen($characters) - 1)];
        }
        return $randomString;
    }
}