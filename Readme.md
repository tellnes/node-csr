# Node CSR

Read CSR files in nodes

## Example

```js
var CSR = require('csr').CSR
  , fs = require('fs')

fs.readFile('file.csr', function(err, file) {
  var csr = new CSR(file)
  console.log(csr.getSubject())
})
```

## Licence

MIT

