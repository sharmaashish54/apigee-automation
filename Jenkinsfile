pipeline {
    agent any
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
	'''
		
            }
        }
    }
}
