import express, { Request, Response } from 'express';
import bcrypt from 'bcrypt';
import User from './models/user';
import session, { Session } from 'express-session';
import dotenv from 'dotenv';

const app = express();

interface CustomSession extends Session {
  userId?: string;
}

app.use(session({
  secret: process.env.SECRET || '',
  resave: false,
  saveUninitialized: true,
  cookie: {
      secure: false,
      httpOnly: true,
      maxAge: 24 * 60 * 60 * 1000,
  }
}));

const requireAuth = (req: Request, res: Response, next: any) => {
  const session = req.session as CustomSession;
  if (session.userId) {
    next();
  } else {
    res.status(401).send('Unauthorized');
  }
};

app.use(express.json());

app.post('/register', async (req: Request, res: Response) => {
    const { username, password } = req.body;

    User.findOne({
      where: {
        username: username
      }
    })
    .then(async user => {
      if(user) {
        res.status(401).send('Such username already exists');
      }
      else {
        const hashedPassword = await bcrypt.hash(password, 10);

        const user = await User.create({
          username,
          password: hashedPassword,
        });

        res.json(user);
      }
    })
    .catch(error => res.status(500).send('Internal Server error'));
});

app.post('/login', (req, res, next) => {
  const { username, password } = req.body;

  User.findOne({
    where: {
      username: username
    }
  })
  .then(user => {
    if(!user) {
      res.status(401).send('No such user found');
    }
    else {
      bcrypt.compare(password, user.password, (error, result) => {
        if(result) {
          (req.session as CustomSession).userId = '{user.id}';
          res.json(user);
        }
        else {
          console.log(error)
          res.status(500).send('Invalid data');
        }
      })
    }
  })
  .catch(error => next(error));
})


app.get('/users', requireAuth, async (req: Request, res: Response) => {
  try {
    const users = await User.findAll();
    res.json(users);
  } catch (error) {
    console.error('Error:', error);
    res.status(500).send('Internal Server Error');
  }
});

const port = 3000;
app.listen(port, () => {
  console.log(`Server is running on http://localhost:${port}`);
});
