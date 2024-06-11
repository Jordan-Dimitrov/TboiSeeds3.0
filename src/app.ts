import express, { Request, Response } from 'express';
import bcrypt from 'bcrypt';
import User from './models/user';

const app = express();

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
    }).catch(error => res.status(500).send('Internal server error'))
});

app.post('/login', (req, res, next) => {
  const { username, password } = req.body;

  User.findOne({
    where: {
      username: req.body.username
    }
  })
  .then(user => {
    if(!user) {
      res.status(401).send('No such user found');
    }
    else {
      bcrypt.compare(req.body.password, user.password, (error, result) => {
        if(result) {
          res.json(user);
        }
        else {
          console.log(error)
          res.status(500).send('Invalid data');
        }
      })
    }
  }).catch(error => res.status(500).send('Internal server error'))
})


app.get('/users', async (req: Request, res: Response) => {
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
