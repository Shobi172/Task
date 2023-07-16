import mongoose, { Schema, Document } from 'mongoose';

export interface IUser extends Document {
  email: string;
  password: string;
  accessToken?: string;
  refreshToken?: string;
}

const UserSchema: Schema = new Schema({
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  accessToken: { type: String },
  refreshToken: { type: String },
});

const User = mongoose.model<IUser>('User', UserSchema);

export default User;
