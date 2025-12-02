import mongoose from 'mongoose'

const userSchema = new mongoose.Schema(
    {
        // id:
        // {
        //     type:String,
        //     required: [true, 'unique key'],
        //     trim: true,
        // },

        username:
        {
            type:String,
            required: [true, 'must provide name'],
            trim: true,
        },

        password:
        {
            type:String,
            required: [true, 'must provide password'],
            trim: true,
            minlength: 4,    
        }
    } , { timestamps: true });


export default mongoose.model('userMongo', userSchema); 
