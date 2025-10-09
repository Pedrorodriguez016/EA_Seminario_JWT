import {sign, verify} from 'jsonwebtoken';
const JWT_SECRET = process.env.JWT_SECRET   || 'defaultsecret';
import {Usuario, IUsuario} from '../models/usuario';
import type {Response} from 'express';



const generateToken = (usuario: IUsuario, res: Response): string =>{
    const payload = { id: usuario._id.toString() };
    
const token : string = sign({payload}, JWT_SECRET, {expiresIn: "30s"});

res.cookie ('token', token, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production' ? true: false, // Asegura que la cookie solo se envíe a través de HTTPS en producción
    sameSite: 'lax',
    maxAge:   60 * 60 * 1000 // La cookie expira en 30 segundos
});

return token;
};
const generateRefreshToken = (usuario: IUsuario, res: Response): string =>{
    const payload = { id: usuario._id.toString() }; 
    const refreshToken : string = sign({payload}, JWT_SECRET, {expiresIn: "1y"});

    res.cookie ('refreshToken', refreshToken, {    
        httpOnly: true,
    secure: process.env.NODE_ENV === 'production' ? true: false, // Asegura que la cookie solo se envíe a través de HTTPS en producción
    sameSite: 'lax', // Previene ataques CSRF
    maxAge: 365 * 24 * 60 * 60 * 1000 // La cookie expira en 24 horas
});
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