const express = require("express")
const router = express.Router()
const mongoose = require('mongoose')
const User = mongoose.model("User")
const bcrypt = require("bcrypt")
const jwt = require("jsonwebtoken")
const {JWT_SECRET} = require("../config/keys")
const requirelogin = require("../middleware/requirelogin")
const nodemailer = require('nodemailer')
const sendgridTransport = require('nodemailer-sendgrid-transport');
const {SENDGRID_API,EMAIL} = require("../config/keys")
const crypto = require("crypto")

const transporter = nodemailer.createTransport(sendgridTransport({
    auth:{
        api_key:SENDGRID_API
    }
}))

router.get('/protected',requirelogin,(req, res)=>{
    res.send("hello user")
})

router.post('/signup', (req,res)=>{
   const {name,email,password} = req.body
   if(!email||!password||!name){
       return res.status(422).json({error:"Please add all the fiels"})
   }
   User.findOne({email: email})
   .then((savedUser)=>{
       if(savedUser){
        return res.status(422).json({error:"user already exist with that email"})
       }
       bcrypt.hash(password,12)
       .then(hashedpassword=>{

            const user = new User({
                email,
                password:hashedpassword,
                name
            })
    
            user.save()
            .then(user=>{
                res.json({message: "user saved successfully"})
            })
    
            .catch(err=>{
                console.log(err)
            })

        })
      
   })
   .catch(err=>{
       console.log(err)
   })
});

router.post('/signin', (req,res)=>{
    const {email,password} = req.body
    if(!email || !password){
        res.status(422).json({error: "please add email or password"})
    }
    User.findOne({email:email})
    .then(savedUser =>{
        if(!savedUser){
           return res.status(422).json({error: "Invalid email or password"})
           
        }

        bcrypt.compare(password, savedUser.password)
        .then(doMatch=>{
            if(doMatch){
                //res.json({message: "Successfully signed in"})
                const token = jwt.sign({_id: savedUser._id}, JWT_SECRET)
                const {_id,name,email} = savedUser
                 res.json({token, user:{_id,name,email}})
            }
            else{
               return res.status(422).json({error: "Invalid email or password"})
            }
            
            
        })
        .catch(err=>{
            console.log(err)
        })
    })
})


router.post('/reset-password',(req,res)=>{
    crypto.randomBytes(32,(err,buffer)=>{
        if(err){
            console.log(err)
        }
        const token = buffer.toString("hex")
        User.findOne({email:req.body.email})
        .then(user=>{
            if(!user){
                return res.status(422).json({error:"User dont exists with that email"})
            }
            user.resetToken = token
            user.expireToken = Date.now() + 3600000
            user.save().then((result)=>{
                transporter.sendMail({
                    to:user.email,
                    from:"faizanhuda12@gmail.com",
                    subject:"password reset",
                    html:`
                    <p>You requested for password reset</p>
                    <h5>click in this <a href="${EMAIL}/reset/${token}">link</a> to reset password</h5>
                    `
                })
                res.json({message:"check your email"})
            })

        })
    })
})


router.post('/new-password',(req,res)=>{
   const newPassword = req.body.password
   const sentToken = req.body.token
   User.findOne({resetToken:sentToken,expireToken:{$gt:Date.now()}})
   .then(user=>{
       if(!user){
           return res.status(422).json({error:"Try again session expired"})
       }
       bcrypt.hash(newPassword,12).then(hashedpassword=>{
          user.password = hashedpassword
          user.resetToken = undefined
          user.expireToken = undefined
          user.save().then((saveduser)=>{
              res.json({message:"password has been updated"})
          })
       })
   }).catch(err=>{
       console.log(err)
   })
})
module.exports = router