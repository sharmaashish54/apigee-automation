pipeline {
    agent any
	environment {
        HOME = '.'
    }
    tools {nodejs "npm"}
    stages {
        stage('generate proxy bundle') {
            steps {
                echo 'Hello World'
                sh label: '', script: '''
	file="./api-proxy-config.properties"
	if [ -f "$file" ]
	then
	name=`sed \'/^\\#/d\' $file | grep \'name\'  | tail -n 1 | cut -d "=" -f2- | sed \'s/^[[:space:]]*//;s/[[:space:]]*$//\'`
	authenticated=`sed \'/^\\#/d\' $file | grep \'authenticated\'  | tail -n 1 | cut -d "=" -f2- | sed \'s/^[[:space:]]*//;s/[[:space:]]*$//\'`
	else
		echo "$file not found."
	fi
	openapi2apigee generateApi ${name} -s ./open-api-spec/${name}.json -d /home/jenkins/agent/workspace/test/
	cd /home/jenkins/agent/workspace/test/${name}/apiproxy/policies
	touch AM-jwt-failed.xml
	echo \'<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
			<AssignMessage async="false" continueOnError="false" enabled="true" name="AM-jwt-failed">
			<DisplayName>AM-jwt-failed</DisplayName>
			<Properties/>
			<Set>
			<Headers/>
			<Payload contentType="application/json">
			{              		"timeStamp":"{system.time.year}-{system.time.month}-{system.time.day}T{system.time.hour}:{system.time.minute}:{system.time.second}.{system.time.millisecond}+0000",
			"code":"401",
			"message":"UnAuthorized access , please enter valid details and try again."
			}
			</Payload>
			<StatusCode>401</StatusCode>
			<ReasonPhrase>UnAuthorized</ReasonPhrase>
			</Set>
			<IgnoreUnresolvedVariables>true</IgnoreUnresolvedVariables>
			<AssignTo createNew="false" transport="http" type="request"/>
			</AssignMessage>\' > AM-jwt-failed.xml
			
	touch AM-set-target-url.xml
	echo \'<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
	<AssignMessage async="false" continueOnError="false" enabled="true" name="AM-set-target-url">
    <DisplayName>AM-set-target-url</DisplayName>
    <FaultRules/>
    <Remove>
        <Headers>
            <Header name="apikey"/>
            <Header name="Content-Length"/>
            <Header name="X-Forwarded-For"/>
            <Header name="X-Forwarded-Port"/>
            <Header name="X-Forwarded-Proto"/>
            <Header name="Postman-Token"/>
            <Header name="Authorization"/>
        </Headers>
    </Remove>
    <IgnoreUnresolvedVariables>true</IgnoreUnresolvedVariables>
    <AssignTo type="request" transport="http" createNew="false"/>
		</AssignMessage>\' > AM-set-target-url.xml
	
	touch basicauth-ms.xml
	echo \'<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
			<BasicAuthentication async="false" continueOnError="false" enabled="true" name="basicauth-ms">
			<DisplayName>basicauth-ms</DisplayName>
			<Operation>Encode</Operation>
			<User ref="ms-username"/>
			<Password ref="ms-password"/>
			<IgnoreUnresolvedVariables>false</IgnoreUnresolvedVariables>
			<AssignTo createNew="false">request.header.Authorization</AssignTo>
			</BasicAuthentication>\' > basicauth-ms.xml
			
	touch KVM-operations-ck-jwt-config.xml
	echo \'<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
			<KeyValueMapOperations async="false" continueOnError="false" enabled="true" name="KVM-operations-ck-jwt-config" mapIdentifier="ck-jwt-config">
			<DisplayName>KVM-operations-ck-jwt-config</DisplayName>
			<FaultRules/>
			<Properties/>
			<ExclusiveCache>false</ExclusiveCache>
			<ExpiryTimeInSecs>-1</ExpiryTimeInSecs>
			<InitialEntries/>
			<Get assignTo="private.publickey">
			<Key>
			<Parameter>key</Parameter>
			</Key>
			</Get>
			<Scope>environment</Scope>
			</KeyValueMapOperations>\' > KVM-operations-ck-jwt-config.xml
	
	touch KVM-operations-ms-ck-config.xml
	echo \'<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
			<KeyValueMapOperations encrypted="false" mapIdentifier="ms-ck-config" async="false" continueOnError="false" enabled="true" name="KVM-operations-ms-ck-config">
			<DisplayName>KVM-operations-ms-ck-config</DisplayName>
			<FaultRules/>
			<Properties/>
			<ExclusiveCache>false</ExclusiveCache>
			<ExpiryTimeInSecs>-1</ExpiryTimeInSecs>
			<InitialEntries/>
			<Get assignTo="service-url">
			<Key>
			<Parameter>service-url</Parameter>
			</Key>
			</Get>
			<Get assignTo="ms-basepath">
			<Key>
			<Parameter>ms-basepath</Parameter>
			</Key>
			</Get>
			<Get assignTo="ms-username">
			<Key>
			<Parameter>ms-username</Parameter>
			</Key>
			</Get>
			<Get assignTo="ms-password">
			<Key>
			<Parameter>ms-password</Parameter>
			</Key>
			</Get>
			<Get assignTo="ck.subject">
			<Key>
			<Parameter>ck_subject</Parameter>
			</Key>
			</Get>
			<Get assignTo="ck.issuer">
			<Key>
			<Parameter>ck_issuer</Parameter>
			</Key>
			</Get>
			<Get assignTo="ck.audience">
			<Key>
			<Parameter>ck_audience</Parameter>
			</Key>
			</Get>
			<Get assignTo="domain">
			<Key>
            <Parameter>domain</Parameter>
			</Key>
			</Get>
			<Scope>environment</Scope>
			</KeyValueMapOperations>\' > KVM-operations-ms-ck-config.xml
	sed -i -e "s;<Parameter>service-url</Parameter>;<Parameter>${name}-service-url</Parameter>;" KVM-operations-ms-ck-config.xml		
			
	touch verify-jwt-ck-token.xml		
	echo \'<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
			<VerifyJWT async="false" continueOnError="false" enabled="true" name="verify-jwt-ck-token">
			<DisplayName>verify-jwt-ck-token</DisplayName>
			<Algorithm>RS256</Algorithm>
			<PublicKey>
			<Value ref="private.publickey"/>
			</PublicKey>
			<Issuer ref="ck.issuer"/>
			</VerifyJWT>\'	> verify-jwt-ck-token.xml
	touch AM-AddCORS.xml
	echo \'<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
	<AssignMessage async="false" continueOnError="false" enabled="true" name="AM-AddCORS">
    <DisplayName>AM-AddCORS</DisplayName>
    <FaultRules/>
    <Properties/>
    <Set>
        <Headers>
            <Header name="Access-Control-Allow-Origin">{domain}</Header>
            <Header name="Access-Control-Allow-Headers">content-type,X-B3-TraceId</Header>
            <Header name="Access-Control-Allow-Credentials">true</Header>
            <Header name="Access-Control-Max-Age">3628800</Header>
            <Header name="Access-Control-Allow-Methods">GET, PUT, POST, DELETE, OPTIONS, PATCH</Header>
        </Headers>
    </Set>
    <IgnoreUnresolvedVariables>true</IgnoreUnresolvedVariables>
    <AssignTo type="response" transport="http" createNew="false"/>
	</AssignMessage>\'	> AM-AddCORS.xml
	
	touch JS-set-target-url.xml
    echo \'<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
        <Javascript async="false" continueOnError="false" enabled="true" timeLimit="200" name="JS-set-target-url">
        <DisplayName>JS-set-target-url</DisplayName>
        <Properties/>
        <ResourceURL>jsc://JS-set-target-url.js</ResourceURL>
        </Javascript>\' > JS-set-target-url.xml
		
	
	touch JS-generate-auth-using-cookie.xml
    echo \'<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
	<Javascript async="false" continueOnError="false" enabled="true" timeLimit="200" name="JS-generate-auth-using-cookie">
    <DisplayName>JS-generate-auth-using-cookie</DisplayName>
    <Properties/>
	<IncludeURL>jsc://JS-base64EncodeDecode.js</IncludeURL>
    <ResourceURL>jsc://generate-auth-using-cookie.js</ResourceURL>
	</Javascript>\' > JS-generate-auth-using-cookie.xml
		
	touch RF-CORSFault.xml
	echo \'<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
	<RaiseFault async="false" continueOnError="false" enabled="true" name="RF-CORSFault">
		<DisplayName>RF-CORSFault</DisplayName>
		<FaultRules/>
		<Properties/>
		<FaultResponse>
			<Set>
				<Headers/>
				<Payload contentType="text/plain"/>
				<StatusCode>200</StatusCode>
				<ReasonPhrase>OK</ReasonPhrase>
			</Set>
		</FaultResponse>
		<IgnoreUnresolvedVariables>true</IgnoreUnresolvedVariables>
		<ShortFaultReason>false</ShortFaultReason>
	</RaiseFault>\' > RF-CORSFault.xml		
		
	cd /home/jenkins/agent/workspace/test/${name}/apiproxy
    mkdir -p resources/jsc
    cd /home/jenkins/agent/workspace/test/${name}/apiproxy/resources/jsc
	
	touch JS-base64EncodeDecode.js
	echo \'var Base64={_keyStr:"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=",encode:function(r){var e,t,a,o,n,c,d,h="",C=0;for(r=Base64._utf8_encode(r);C<r.length;)o=(e=r.charCodeAt(C++))>>2,n=(3&e)<<4|(t=r.charCodeAt(C++))>>4,c=(15&t)<<2|(a=r.charCodeAt(C++))>>6,d=63&a,isNaN(t)?c=d=64:isNaN(a)&&(d=64),h=h+Base64._keyStr.charAt(o)+Base64._keyStr.charAt(n)+Base64._keyStr.charAt(c)+Base64._keyStr.charAt(d);return h},decode:function(r){var e,t,a,o,n,c,d="",h=0;for(r=r.replace(/[^A-Za-z0-9\\+\\/\\=]/g,"");h<r.length;)e=Base64._keyStr.indexOf(r.charAt(h++))<<2|(o=Base64._keyStr.indexOf(r.charAt(h++)))>>4,t=(15&o)<<4|(n=Base64._keyStr.indexOf(r.charAt(h++)))>>2,a=(3&n)<<6|(c=Base64._keyStr.indexOf(r.charAt(h++))),d+=String.fromCharCode(e),64!=n&&(d+=String.fromCharCode(t)),64!=c&&(d+=String.fromCharCode(a));return d=Base64._utf8_decode(d)},_utf8_encode:function(r){r=r.replace(/\\r\\n/g,"\\n");for(var e="",t=0;t<r.length;t++){var a=r.charCodeAt(t);a<128?e+=String.fromCharCode(a):a>127&&a<2048?(e+=String.fromCharCode(a>>6|192),e+=String.fromCharCode(63&a|128)):(e+=String.fromCharCode(a>>12|224),e+=String.fromCharCode(a>>6&63|128),e+=String.fromCharCode(63&a|128))}return e},_utf8_decode:function(r){for(var e="",t=0,a=c1=c2=0;t<r.length;)(a=r.charCodeAt(t))<128?(e+=String.fromCharCode(a),t++):a>191&&a<224?(c2=r.charCodeAt(t+1),e+=String.fromCharCode((31&a)<<6|63&c2),t+=2):(c2=r.charCodeAt(t+1),c3=r.charCodeAt(t+2),e+=String.fromCharCode((15&a)<<12|(63&c2)<<6|63&c3),t+=3);return e}};\' > JS-base64EncodeDecode.js
	
   
    touch JS-set-target-url.js
    echo \'var proxyPathSuffix = context.getVariable("proxy.pathsuffix");
	var url = context.getVariable("ms-basepath") + context.getVariable("service-url") + proxyPathSuffix;
	var queryParams = context.getVariable("request.querystring");
	if(queryParams!==null){
    url = url + "?"+queryParams;
	}
	context.setVariable("target.url",  url);
    var impersonated_gpssaId = context.getVariable("impersonated_gpssaId");	

	if(impersonated_gpssaId!==null){
    context.setVariable("request.header.gpssaId",impersonated_gpssaId);
	}else{
	context.setVariable("request.header.gpssaId",context.getVariable("jwt.verify-jwt-ck-token.decoded.claim.gpssa_id"));	
	}\' > JS-set-target-url.js
	
	touch generate-auth-using-cookie.js
	echo \'var cookie = context.getVariable("request.header.Cookie");
	if(cookie){
	var tokenValue = cookie && cookie.split(";").find(function(row){
    return row.trim().startsWith("gpssa_auth_token");
	}).split("=")[1];
	if(tokenValue){
	tokenValue = "Bearer " + tokenValue;
	context.setVariable("request.header.Authorization",tokenValue); 
	}	
	var impersonated_cookie_str = cookie && cookie.split(";").find(function(row){
    return row.trim().startsWith("gpssa_auth_impersonated");
	});

	if (impersonated_cookie_str)
    {
     var impersonated_cookie = impersonated_cookie_str.split("=")[1];
     var impersonated_gpssaId = Base64.decode(impersonated_cookie);
     context.setVariable("impersonated_gpssaId",impersonated_gpssaId);
    }
	}\' > generate-auth-using-cookie.js

			if [ "${authenticated}" = "y" ]; then
			
		cd /home/jenkins/agent/workspace/test/${name}/apiproxy/proxies
		
		sed -i -r -e 's|<Request.*>||1' -i -e 's;<PreFlow name="PreFlow">;<FaultRules><FaultRule name="JWT_policy_failed"><Step><Name>AM-jwt-failed</Name></Step><Condition>JWT.verify-jwt-ck-token.failed ="true"</Condition></FaultRule></FaultRules><DefaultFaultRule name="GenericFault"><Step><Name>AM-AddCORS</Name></Step><AlwaysEnforce>true</AlwaysEnforce></DefaultFaultRule><PreFlow name="PreFlow"><Request><Step><Name>KVM-operations-ck-jwt-config</Name><Condition>(request.verb != "OPTIONS")</Condition></Step><Step><Name>KVM-operations-ms-ck-config</Name></Step><Step><Name>JS-generate-auth-using-cookie</Name><Condition>(request.verb != "OPTIONS")</Condition></Step><Step><Name>verify-jwt-ck-token</Name><Condition>(request.verb != "OPTIONS")</Condition></Step></Request>;' -i -e 's;<Flows>;<Flows><Flow name="CORS"><Description>CORS</Description><Request><Step><FaultRules/><Name>RF-CORSFault</Name></Step></Request><Response/><Condition>(proxy.pathsuffix ~~ ".*") and (request.verb = "OPTIONS")</Condition></Flow>;' default.xml

		cd /home/jenkins/agent/workspace/test/${name}/apiproxy/targets
		sed -i -r -e 's|<Request.*>||1' -i -r -e 's|<Response.*>||1' -i -e 's;<PreFlow name="PreFlow">;<PreFlow name="PreFlow"><Request><Step><FaultRules/><Name>AM-set-target-url</Name></Step><Step><Name>basicauth-ms</Name></Step><Step><Name>JS-set-target-url</Name></Step></Request><Response><Step><Name>AM-AddCORS</Name></Step></Response>;' default.xml
	fi;
	'''
		
            }
        }
	stage('zip Proxy bundle') {
    steps{ 
	withCredentials([usernamePassword(credentialsId: 'APIGEE-Credentials', passwordVariable: 'password', usernameVariable: 'username')]) {
		sh label: '', script: '''
		file="./api-proxy-config.properties"
		if [ -f "$file" ]
		then
			name=`sed \'/^\\#/d\' $file | grep \'name\'  | tail -n 1 | cut -d "=" -f2- | sed \'s/^[[:space:]]*//;s/[[:space:]]*$//\'`
			targetURL=`sed \'/^\\#/d\' $file | grep \'targetURL\'  | tail -n 1 | cut -d "=" -f2- | sed \'s/^[[:space:]]*//;s/[[:space:]]*$//\'`
		else
			echo "$file not found."
		fi
        cd /home/jenkins/agent/workspace/test/${name}
		apigeetool deployproxy -u $username -o asharma383-eval -e test -L https://api.enterprise.apigee.com -n ${name} -p $password -d .
		bestzip apiproxy.zip apiproxy
		'''
	
	}
    }
   }
   stage('create entry in kvm'){
   steps{
   withCredentials([usernamePassword(credentialsId: 'APIGEE-Credentials', passwordVariable: 'password', usernameVariable: 'username')]) {
		sh label: '', script: '''
		file="api-proxy-config.properties"
		if [ -f "$file" ]
		then
			name=`sed \'/^\\#/d\' $file | grep \'name\'  | tail -n 1 | cut -d "=" -f2- | sed \'s/^[[:space:]]*//;s/[[:space:]]*$//\'`
			targetURL=`sed \'/^\\#/d\' $file | grep \'targetURL\'  | tail -n 1 | cut -d "=" -f2- | sed \'s/^[[:space:]]*//;s/[[:space:]]*$//\'`
		else
			echo "$file not found."
		fi
		curl --silent --write-out "HTTPSTATUS:%{http_code}" -X POST --header 'Content-Type: application/json' -d '{"name" :"ms-ck-config","entry":[{"name":  "'$name'-service-url","value" : "'$targetURL'"}]}' -u $username:$password 'https://api.enterprise.apigee.com/v1/organizations/asharma383-eval/environments/test/keyvaluemaps/ms-ck-config'
		
		'''
		}
	 }
   }
    }
}




