import { Request, Response, NextFunction } from "express";
import { verifyToken } from "./token";

export function authenticateToken(req: Request, res: Response, next: NextFunction) {
  
  let token : string = req.cookies?.token;
  

  if (!token) {
    const authHeader = req.headers["authorization"];
    token = (authHeader && authHeader.split(" ")[1]) ?? ""; // Bearer <token>
  }

  if (!token) {
    return res.status(401).json({ error: "Token requerido" });
  }

  const decoded = verifyToken(token);
  if (!decoded) {
    return res.status(403).json({ error: "Token inválido o expirado" });
  }

  (req as any).user = decoded;

  console.log("Token verificado, usuario:", decoded);
  next();
}