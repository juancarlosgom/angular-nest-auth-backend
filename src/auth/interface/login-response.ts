import { User } from "../entities/user.entity";



export interface LoginRespone {

    user: User;
    token: string;

}