import { Usuario, IUsuario } from '../models/usuario';

export class UserService {
    async createUser(user: Partial<IUsuario>): Promise<IUsuario | null> {
        try {
          const newUser = new Usuario(user);
          return await newUser.save();
        } catch (error) {
          throw new Error((error as Error).message);
        }
      }
      
    async getAllUsers(): Promise<IUsuario[] | null> {
      return await Usuario.find();
    }

    async getUserById(id: string): Promise<IUsuario | null> {
      return await Usuario.findById(id);
    }

    async getUserByUsername(username: string): Promise<IUsuario | null> {
      return await Usuario.findOne({ username });
    }

    async updateUserById(id: string, user: Partial<IUsuario>): Promise<IUsuario | null> {
      return await Usuario.findByIdAndUpdate(id, user, { new: true });
    }

    async updateUserByUsername(username: string, user: Partial<IUsuario>): Promise<IUsuario | null> {
      
        return await Usuario.findOneAndUpdate({ username }, user, { new: true });
    }

    async deleteUserById(id: string): Promise<IUsuario | null> {

      return await Usuario.findByIdAndDelete(id);
    }

    async deleteUserByUsername(username: string): Promise<IUsuario | null> {
        return await Usuario.findOneAndDelete({ username });
    }



}