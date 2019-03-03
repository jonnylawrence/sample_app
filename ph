#!/bin/sh

read -p "Commit title:" ctitle
git add -A
git commit -m $ctitle
echo "Pushing Heroku***********>"
git push heroku master
echo "Push github*************>"
git push
echo "Tailing heroku*********>"
heroku logs --tail
