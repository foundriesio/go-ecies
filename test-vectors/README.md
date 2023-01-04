Test vectors are generated from the tests themselves as there is no free vectors available.

The tests print data in YAML format which is easier to manipulate.
But, the tests use JSON format as we don't want to maintain the yaml dependency.

In order to initialize the YAML to JSON transformer, run this script:
```
go get github.com/bronze1man/yaml2json
go install github.com/bronze1man/yaml2json
git checkout -- go.*
```
It installs the yaml2json utility and cleans unnecessary deps in go.mod.

Also, install the `jq` utility if you want to pretty print the JSON files:
```
apt-get install jq
```

Then, in order to generate the JSON vector, run this:
```
~/go/bin/yaml2json <test-vectors/$VECTOR.yml | jq . >test-vectors/$VECTOR.json
```
