def flag = false
pipeline {
    agent any
    stages {
        stage('Build') {
            steps {
                echo 'Building..'
            }
        }
        stage('Test') {
            steps {
                echo 'Testing..'
            }
        }
        stage('Deploy') {
            steps {
                echo 'Deploying....'
            }
        }
        stage('Test') {
        when {
            expression { flag == true } 
        }
        steps {
            echo 'Testing..'
        }
    }
    }
    post {
        always {
            echo 'Post build condition running'
        }
        failure {
            echo 'Post Action if Build Failed'
        }
    }
}
