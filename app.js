const express = require("express");
const app = express();
const mongoose = require("mongoose")
const bodyParser = require("body-parser");
const {MONGOURI} = require("./config/keys")
const PORT = process.env.PORT || 3000



mongoose.connect(MONGOURI,{
    useNewUrlParser: true,
    useUnifiedTopology: true
})
mongoose.connection.on('connected',()=>{
    console.log("connection to db succesfull")
});

mongoose.connection.on('error',(err)=>{
    console.log(err)
});

require('./models/user')
require('./models/post')

app.use(express.json())

app.use(require('./routes/auth'))
app.use(require('./routes/post'))
app.use(require('./routes/user'))

app.get("/", function(req,res){
  res.send("Hello");
});

if(process.env.NODE_ENV=="production"){

  app.use(express.static('client/build'))

  const path = require('path')

  app.get("*",(req,res)=>{

      res.sendFile(path.resolve(__dirname,'client','build','index.html'))

  })

}



app.listen(PORT,()=>{

  console.log("server is running on",PORT)

})