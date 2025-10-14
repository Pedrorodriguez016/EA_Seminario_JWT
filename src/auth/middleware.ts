import { Request, Response, NextFunction } from "express";
import { verifyToken, verifyRefreshToken } from "./token";

export function authenticateToken(req: Request, res: Response, next: NextFunction) {
  
 
    const authHeader = req.headers["authorization"];
    const token: string = (authHeader && authHeader.split(" ")[1]) ?? ""; // Bearer <token>
  

  if (!token) {
    return res.status(401).json({ error: "Token requerido" });
  }

  const decoded = verifyToken(token);
  if (!decoded) {
    return res.status(403).json({ error: "Token inválido o expirado" });
  }

  (req as any).user = decoded;

  const tokenUserid : string = (decoded as any).payload.id;
  const requestUserid : string = req.params.id;
  if (requestUserid && tokenUserid !== requestUserid) {
    return res.status(403).json({ error: "No autorizado para acceder a este recurso" });
  }

  console.log("Token verificado, usuario:", decoded);
  next();
}
export function authenticateRefreshToken(req: Request, res: Response, next: NextFunction) {
  try {
    const { refreshToken } = req.body;

    if (!refreshToken) {
      return res.status(401).json({ error: "Refresh token requerido" });
    }

    const decoded = verifyRefreshToken(refreshToken);
    if (!decoded) {
      return res.status(403).json({ error: "Refresh token inválido o expirado" });
    }
    
    (req as any).user = decoded;

    console.log("Refresh token verificado correctamente:", decoded);
    next();
  } catch (error) {
    console.error("Error al verificar refresh token:", error);
    return res.status(500).json({ error: "Error interno en la verificación del refresh token" });
  }
}