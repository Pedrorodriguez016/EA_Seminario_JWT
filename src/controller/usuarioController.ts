import { Request, Response } from 'express';
import { IUsuario } from '../models/usuario';
import { UserService } from '../services/usuarioServices';
import { validationResult } from "express-validator";
import { generateToken, verifyToken, generateRefreshToken } from '../auth/token';
import { authenticateToken } from '../auth/middleware';
import { access } from 'fs';
import { Console } from 'console';

const userService = new UserService();

export async function createUser(req: Request, res: Response): Promise<Response> {
  console.log('crear usuario');
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }
  try {
    const { username, gmail, password, birthday } = req.body as IUsuario;
    const newUser: Partial<IUsuario> = { username, gmail, password, birthday };
    const user = await userService.createUser(newUser);

    return res.status(201).json({
      message: 'USUARIO CREADO CON EXITO',
      user
    });
  } catch (error) {
    return res.status(500).json({ error: 'FALLO AL CREAR EL USUARIO' });
  }
  }

  export async function getAllUsers(req: Request, res: Response): Promise<Response> {
  console.log('obtener todos los usuarios');
  try {
    const users = await userService.getAllUsers();
    return res.status(200).json(users);
  } catch (error) {
    return res.status(404).json({ message: (error as Error).message });
  }
  }

  export async function getUserById(req: Request, res: Response): Promise<Response> {
  console.log('obtener usuario por id');
  try {
    const { id } = req.params;
    const user = await userService.getUserById(id);
    if (!user) {
      return res.status(404).json({ message: 'USUARIO NO ENCONTRADO' });
    }
    return res.status(200).json(user);
  } catch (error) {
    return res.status(400).json({ message: (error as Error).message });
  }
  }

  export async function getUserByUsername(req: Request, res: Response): Promise<Response> {
  console.log('obtener usuario por username');
  try {
    const { username } = req.params;
    const user = await userService.getUserByUsername(username);
    if (!user) {
      return res.status(404).json({ message: 'USUARIO NO ENCONTRADO' });
    }
    return res.status(200).json(user);
  } catch (error) {
    return res.status(400).json({ message: (error as Error).message });
  }
  }


  export async function updateUserById(req: Request, res: Response): Promise<Response> {
  console.log('actualizar usuario por id');
   try {
    const userFromToken = (req as any).user;

    if (!userFromToken) {
      return res.status(401).json({ message: "Token requerido" });
    }

    const { id } = req.params;
    console.log('id param:', id); 
    console.log('id from token:', userFromToken.payload.id);
    
    if (userFromToken.payload.id !== id) {
      return res.status(403).json({ message: "No tienes permisos para modificar a otro usuario" });
    }

    const userData: Partial<IUsuario> = req.body;
    const updatedUser = await userService.updateUserById(id, userData);
    console.log('Usuario actualizado:', updatedUser);
    if (!updatedUser) {
      return res.status(404).json({ message: "USUARIO NO ENCONTRADO" });
    }


    return res.status(200).json({
      message: "Usuario actualizado correctamente",
      user: updatedUser,
    });
  } catch (error) {
    return res.status(400).json({ message: (error as Error).message });
  }
  }

  export async function updateUserByUsername(req: Request, res: Response): Promise<Response> {
  try {
    const userFromToken = (req as any).user;

    if (!userFromToken) {
      return res.status(401).json({ message: "Token requerido" });
    }

    const { username } = req.params;
    console.log('username param:', username); 
    console.log('user from token:', userFromToken.usuario.username);
  
    if (userFromToken.usuario !== username) {
      return res.status(403).json({ message: "No tienes permisos para modificar a otro usuario" });
    }

    const userData: Partial<IUsuario> = req.body;
    const updatedUser = await userService.updateUserByUsername(username, userData);

    if (!updatedUser) {
      return res.status(404).json({ message: "USUARIO NO ENCONTRADO" });
    }



    return res.status(200).json({
      message: "Usuario actualizado correctamente",
      user: updatedUser,
    
    });
  } catch (error) {
    return res.status(400).json({ message: (error as Error).message });
  }
  }



  export async function deleteUserById(req: Request, res: Response): Promise<Response> {
  console.log('eliminar usuario por id');
  try {
    const { id } = req.params;
    const deletedUser = await userService.deleteUserById(id);
    if (!deletedUser) {
      return res.status(404).json({ message: 'USUARIO NO ENCONTRADO' });
    }
    return res.status(200).json(deletedUser);
  } catch (error) {
    return res.status(400).json({ message: (error as Error).message });
  }
  }


  export async function deleteUserByUsername(req: Request, res: Response): Promise<Response> {
  try {
    const { username } = req.params;
    const deletedUser = await userService.deleteUserByUsername(username);
    if (!deletedUser) {
      return res.status(404).json({ message: 'USUARIO NO ENCONTRADO' });
    }
    return res.status(200).json(deletedUser);
  } catch (error) {
    return res.status(400).json({ message: (error as Error).message });
  }
  }
 

  export async function login(req: Request, res: Response): Promise<Response> {
  try {
    const { user, password } = req.body;

    if (!user|| !password) {
      return res.status(400).json({ error: "Faltan credenciales" });
    }

    // Service que valida usuario + password
    const User = await userService.getUserByUsername(user);
    if (!user) {
      return res.status(401).json({ error: "Usuario no encontrado" });
    }
    
    // Generar token
    
    const token = await generateToken(User!, res);
    const refreshToken = await generateRefreshToken(User!, res);
    return res.status(200).json({
      User,
      message: "LOGIN EXITOSO",
      
    });
  } catch (error) {
    return res.status(500).json({ error: "Error en el login" });
  }

}
export async function refreshAccessToken(req: Request, res: Response): Promise<Response> {
  try {
    const refreshToken = req.cookies.refreshToken;

    if (!refreshToken) {
      return res.status(401).json({ message: "No se encontró el refresh token" });
    }

   const decoded = verifyToken(refreshToken) as any;
    const userId = decoded?.payload?.id;
    if (!userId) {
      console.log("Refresh token inválido o expirado:", decoded);
      return res.status(403).json({ message: "Refresh token inválido o expirado" });
    }

    const user = await userService.getUserById(decoded.id);
    if (!user) {
      return res.status(404).json({ message: "Usuario no encontrado" });
    }
    generateToken(user, res);
    return res.status(200).json({ message: "Access token renovado correctamente" });
  } catch (error) {
    console.error("Error al refrescar token:", error);
    return res.status(500).json({ message: "Error interno al refrescar el token" });
  }
}
export async function logout(req: Request, res: Response): Promise<Response> {
  res.clearCookie('authToken', {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict'
  });
  
  return res.status(200).json({ message: "Logout exitoso" });
  }
