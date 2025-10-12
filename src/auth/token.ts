import {sign, verify} from 'jsonwebtoken';
const JWT_SECRET = process.env.JWT_SECRET   || 'defaultsecret';
import {Usuario, IUsuario} from '../models/usuario';
import type {Response} from 'express';



const generateToken = (usuario: IUsuario, res: Response): string =>{
    const payload = { id: usuario._id.toString() };
    
const token : string = sign({payload}, JWT_SECRET, {expiresIn: "15s"});


return token;
};
const generateRefreshToken = (usuario: IUsuario, res: Response): string =>{
    const payload = { id: usuario._id.toString() }; 
    const refreshToken : string = sign({payload}, JWT_SECRET, {expiresIn: "1y"});

return refreshToken;
}       

const verifyToken = (token : string) =>{
    try {
        const decoded = verify(token, JWT_SECRET);
        return decoded;
} 
    catch (error) {
        return null;
}  
};
export{generateToken, verifyToken, generateRefreshToken}; 