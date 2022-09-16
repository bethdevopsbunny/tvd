# tvd
## tenable vulnerability diff

tenable vulnerability diff is a pipeline utility leveraging [tenable api](https://developer.tenable.com/reference/navigate)
to check you haven't introduced new vulnerabilities into your deployment.

## authentication
 authentication is handled by storing a tenable api key in an environment variable TENABLE_API_KEY 
    

## arguments


### run 

tvd run [flags]


| flags        | short hand | type   |description                                                              | default | mandatory |
|--------------|------------|--------|------------------------------------------------------------------------|---------|-----------|
| --help       |  ------          |  ------      |help for this command                                                    |    ------     |    ------       |
| --scan-name  | -s         | string |target scan you wish to diff                                             |    ------     | yes       |
| --critical   | -c         | bool   |if set to false will omit critical results                               | true    | no        |
| --high       | -h         | bool   |if set to false will omit high results                                   | true    | no        |
| --medium     | -m         | bool   |if set to false will omit medium results                                 | true    | no        |
| --low        | -l         | bool   |if set to false will omit low results                                    | true    | no        |
| --no-scan    | -n         | bool   |runs the diff without triggering a new scan                              | false   | no        |
| --exit-with-error | -e         | bool   |returns errorcode 1 if increase to vulnerabilities                       | false   | no        |
| --top        | -t         | int    |clamp the number of vulnerabilities <br/> returned in NewVulnerabilities | 30      | no        |
| --verbose    | -v         | int    |Displays Logging                                        | 0       | no        |

### ci example

```
version: 2.1
jobs:
  launch_tvd:
    docker:
      - image: cimg/go:1.19.1
    steps:

      - checkout

      - run:
          name: "tvd download"
          command: |
            sudo wget https://github.com/bethdevopsbunny/tvd/releases/download/v0.1/tvd.linux -O /usr/local/bin/tvd
            sudo chmod +x /usr/local/bin/tvd

      - run:
          name: "tvd run"
          command: |
           tvd run --scan-name << pipeline.scan-name >> --no-scan=true --verbose=1 --exit-with-error=true | jq  

workflows:
  version: 2
  build:
    jobs:
      - launch_tvd

```
