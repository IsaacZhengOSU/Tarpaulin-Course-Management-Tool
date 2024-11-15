const express = require('express');
const app = express();
app.use(express.json());
const https = require('https');
const multer = require('multer')
const upload = multer().single('file');
app.set("port", 8080);

// Jwt modules
var jwksClient = require('jwks-rsa');
var jwt = require('jsonwebtoken');

const { Datastore, PropertyFilter } = require('@google-cloud/datastore');
const datastore = new Datastore();
const { Storage } = require('@google-cloud/storage');
const storage = new Storage();
const bucketName = 'as06-zhengzho-nodejs';
// const bucket = storage.bucket('');

const localIp = "https://as06-424614.uw.r.appspot.com"
const client_info = {
    'domain': 'as05-nodejs.us.auth0.com',
    "grant_type": "password",
    "client_id": "4j0xwmeM4h6C94K9FgxKGNWpNG79uHHE",
    "client_secret": "izGyZ3NMir7wnNmBItTx2ysxb4hB4JcHqacobvVR_QGEAjJz31cEIqRLOs1HsqiK"
}

//error code table
const errTable = {
    "400": { "Error": "The request body is invalid" },
    "401": { "Error": "Unauthorized" },
    "403": { "Error": "You don't have permission on this resource" },
    "404": { "Error": "Not found" },
    "409": { "Error": "Enrollment data is invalid" }
}


/*******************************************
 * Jwt checking functions
*******************************************/
const client = jwksClient({ jwksUri: 'https://' + client_info.domain + '/.well-known/jwks.json' });
function getKey(header, next) {
    client.getSigningKey(header.kid, function (err, key) {
        var signingKey = key.publicKey || key.rsaPublicKey;
        next(null, signingKey);
    });
}
async function verify_jwt(req, payload) {
    if (req.headers.authorization && req.headers.authorization.split(" ")[0] === "Bearer") {
        const token = req.headers.authorization.split(" ")[1];
        let p = new Promise((resolve, reject) => {
            jwt.verify(token, getKey, function (err, decoded) {
                if (err) reject(err);
                else resolve(decoded);
            });
        });
        await p.then(
            function (value) { payload = value; },
            function (error) { payload = null; console.log(error); }
        )
        return payload;
    } else {
        return null;
    }
}

/*******************************************
 * HATEOAS functions
*******************************************/
function getUrl(req, obj, C_OR_R_OR_O) {
    if (C_OR_R_OR_O === 'c' || C_OR_R_OR_O === 'C') {
        var newUrl = localIp + req.url + '/' + obj.id;
    } else if (C_OR_R_OR_O === 'r' || C_OR_R_OR_O === 'R') {
        var newUrl = localIp + req.url;
    } else {
        var newUrl = localIp + '/users/' + obj.id;
    }
    obj.self = newUrl;
    return obj;
}

function getUrlA(req, obj) {
    var avatarUrl = localIp + '/users/' + Object.values(req.params)[0] + '/avatar';
    obj.avatar_url = avatarUrl;
    return obj;
}

/*******************************************
 * Pagination functions
*******************************************/
async function runPageQuery(pageCursor, offset) {
    let query = datastore.createQuery('courses').order('subject').limit(3);
    if (pageCursor) query = query.start(pageCursor);
    const results = await datastore.runQuery(query);
    const entities = results[0];
    const info = results[1];
    if (offset !== 0) {
        offset = offset - 3;
        const results = await runPageQuery(info.endCursor, offset);
        return results;
    }
    return entities;
}

/*******************************************
*    ENDPOINTS
*******************************************/
// 1. User login
app.post('/users/login', async (req, res) => {
    try {
        const username = req.body.username;
        const password = req.body.password;
        const body = {
            "grant_type": "password",
            "username": username,
            "password": password,
            "client_id": client_info.client_id,
            "client_secret": client_info.client_secret
        }
        const dataString = JSON.stringify(body);

        const options = {
            hostname: client_info.domain,
            path: '/oauth/token',
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Content-Length': dataString.length,
            }
        };
        let p = new Promise((resolve, reject) => {
            const req = https.request(options, (res) => {
                let data = '';
                res.on('data', (chunk) => { data += chunk.toString(); });
                res.on('end', () => { resolve(JSON.parse(data)) });
            });
            req.on('error', (err) => { reject(err); })
            req.write(dataString);
            req.end();
        });
        await p.then(
            function (value) {
                if (Object.hasOwn(value, "error")) {
                    if (value.error === "invalid_request") { res.status(400).send(errTable[400]).end(); }
                    else if (value.error === "invalid_grant") { res.status(401).send(errTable[401]).end(); }
                } else {
                    const retObj = { "token": value.id_token }
                    res.status(200).send(retObj).end()
                }
            },
            function (error) { console.log(error); }
        )
    } catch (err) {
        console.log(err);
        res.status(400).send(errTable[400]).end();
    }
});

// 2. Get all users
app.get("/users", async function (req, res) {
    var payload = await verify_jwt(req, payload);
    if (!payload) res.status(401).send(errTable[401]).end();
    else {
        const query = datastore.createQuery('users').filter(new PropertyFilter('sub', '=', payload.sub));
        datastore.runQuery(query, (err, entities) => {
            if (entities[0].role !== "admin") res.status(403).send(errTable[403]).end();
            else {
                const query1 = datastore.createQuery('users');
                datastore.runQuery(query1, (err, entities) => {
                    var resBody = [];
                    if (entities.length !== 0) {
                        entities.forEach(function (arrayItem) {
                            delete arrayItem.avatar;
                            resBody.push(Object.assign({ id: parseInt(arrayItem[datastore.KEY].id) }, arrayItem));
                        });
                        res.status(200).send(resBody).end();
                    };
                });
            }
        });
    }
});

// 3. Get a user
app.get("/users/:user_id", async function (req, res) {
    var payload = await verify_jwt(req, payload);
    if (!payload) res.status(401).send(errTable[401]).end();
    else {
        // check if user_id existed and is a admin and if jwt id is the path id
        const key = datastore.key(['users', parseInt(req.params.user_id)]);
        datastore.get(key, async function (err, userEntity) {
            if (!userEntity || ((userEntity.sub !== "admin") && (payload.sub !== userEntity.sub))) res.status(403).send(errTable[403]).end();
            else {
                userEntity.id = parseInt(req.params.user_id);   // append id to result obj
                // replace avatar file name to avatar_url
                if (userEntity.hasOwnProperty('avatar')) userEntity.avatar_url = localIp + '/users/' + req.params.user_id + '/avatar';
                delete userEntity.avatar;
                // append courses to instructor
                if (userEntity.role == "instructor") {
                    const instructorQuery = datastore.createQuery('courses')
                        .filter(new PropertyFilter('instructor_id', '=', parseInt(req.params.user_id)));
                    datastore.runQuery(instructorQuery, async (err, instrCourEntities) => {
                        userEntity.courses = [];
                        for (i in instrCourEntities) { userEntity.courses.push(localIp + "/courses/" + instrCourEntities[i][datastore.KEY].id); }
                        return res.status(200).send(userEntity).end();
                    })
                    // append courses to student
                } else if (userEntity.role == "student") {
                    const instructorQuery = datastore.createQuery('courses');
                    datastore.runQuery(instructorQuery, async (err, studCourEntities) => {
                        userEntity.courses = [];
                        studCourEntities.forEach(async (element) => {
                            if (element.enrollment) {
                                if (element.enrollment.includes(userEntity.id))
                                    userEntity.courses.push(localIp + "/courses/" + element[datastore.KEY].id);
                            }
                        })
                        return res.status(200).send(userEntity).end();
                    })
                } else res.status(200).send(userEntity).end();
            }
        });
    }
});

// 4. Create/update a user’s avatar
app.post('/users/:user_id/avatar', async function (req, res) {
    upload(req, res, async function (err) {
        if (err instanceof multer.MulterError) {
            res.status(400).send(errTable[400]).end();
            console.log(err);
        } else if (err) {
            res.status(400).send(errTable[400]).end();
            console.log(err);
        }
        else {
            var payload = await verify_jwt(req, payload);
            if (!payload) res.status(401).send(errTable[401]).end();
            else {
                const key = datastore.key(['users', parseInt(req.params.user_id)]);
                datastore.get(key, async function (err, entity) {
                    if (payload.sub !== entity.sub) res.status(403).send(errTable[403]).end();
                    else {
                        const fileName = entity.sub + "_" + req.file.originalname;
                        await storage.bucket(bucketName).file(fileName).save(req.file.buffer);
                        const taskKey = datastore.key(['users', parseInt(req.params.user_id)]);
                        const entity1 = {
                            key: taskKey,
                            data: {
                                "avatar": fileName,
                                "role": entity.role,
                                "sub": entity.sub
                            }
                        };
                        datastore.update(entity1, (err) => { var obj = {}; res.status(200).send(getUrlA(req, obj)); });
                    }
                })
            }
        }
    })
})

// 5. Get a user’s avatar
app.get("/users/:user_id/avatar", async function (req, res) {
    var payload = await verify_jwt(req, payload);
    if (!payload) res.status(401).send(errTable[401]).end();
    else {
        const key = datastore.key(['users', parseInt(req.params.user_id)]);
        datastore.get(key, async function (err, entity) {
            if (payload.sub !== entity.sub) res.status(403).send(errTable[403]).end();
            else {
                if (!entity.avatar) res.status(404).send(errTable[404]).end();
                else {
                    const contents = await storage.bucket(bucketName).file(entity.avatar).download();
                    res.contentType('image/png');
                    res.send(Buffer.from(contents[0], 'binary'));
                }
            }
        })
    }
})

// 6. Delete a user’s avatar
app.delete('/users/:user_id/avatar', async function (req, res) {
    var payload = await verify_jwt(req, payload);
    if (!payload) res.status(401).send(errTable[401]).end();
    else {
        const key = datastore.key(['users', parseInt(req.params.user_id)]);
        datastore.get(key, async function (err, entity) {
            if (payload.sub !== entity.sub) res.status(403).send(errTable[403]).end();
            else {
                if (!entity.avatar) res.status(404).send(errTable[404]).end();
                else {
                    await storage.bucket(bucketName).file(entity.avatar).delete();
                    const taskKey = datastore.key(['users', parseInt(req.params.user_id)]);
                    const entity1 = {
                        key: taskKey,
                        data: {
                            "avatar": undefined,
                            "role": entity.role,
                            "sub": entity.sub
                        }
                    };
                    datastore.update(entity1, (err) => { res.status(204).end(); });
                }
            }
        })
    }
})

// 7. Create a course
app.post('/courses', async function (req, res) {
    var payload = await verify_jwt(req, payload);
    if (!payload) res.status(401).send(errTable[401]).end();
    else {
        const query = datastore.createQuery('users').filter(new PropertyFilter('sub', '=', payload.sub));
        datastore.runQuery(query, (err, entities) => {
            if (entities[0].role !== "admin") res.status(403).send(errTable[403]).end();
            else {
                if (Object.keys(req.body).length < 5) res.status(400).send(errTable[400]);
                else {
                    const key = datastore.key(['users', parseInt(req.body.instructor_id)]);
                    datastore.get(key, async function (err, entity) {
                        if (entity.role !== "instructor") res.status(400).send(errTable[400]);
                        else {
                            const key1 = datastore.key('courses');
                            const newData = {
                                instructor_id: req.body.instructor_id,
                                subject: req.body.subject,
                                number: req.body.number,
                                title: req.body.title,
                                term: req.body.term
                            };
                            datastore.save({ key: key1, data: newData }, (err) => {
                                if (!err) {
                                    datastore.get(key1, function (err, entity) {
                                        const resBody = Object.assign({ id: parseInt(key1.path[1]) }, entity);
                                        res.status(201).send(getUrl(req, resBody, 'c'));
                                    });
                                }
                            });
                        }
                    })
                }
            }
        })
    }
});

// 8. Get all courses
app.get("/courses", async function (req, res) {
    var offset = req.query.offset;
    if (!offset) offset = 0;
    var resBody = {};
    resBody.courses = await runPageQuery(0, offset);
    resBody.courses.forEach(async (element) => {
        element.id = parseInt(element[datastore.KEY].id);
        element.self = localIp + "/courses/" + element[datastore.KEY].id;
    })
    resBody.next = localIp + req.url + "?limit=3&offset=" + (parseInt(offset) + 3);
    res.status(200).send(resBody).end();
});

// 9. Get a course
app.get("/courses/:course_id", async function (req, res) {
    const key = datastore.key(['courses', parseInt(req.params.course_id)]);
    datastore.get(key, async function (err, entity) {
        if (entity === undefined) {
            res.status(404).send(errTable[404]).end();
        } else {
            entity.id = parseInt(req.params.course_id);
            entity.self = localIp + "/courses/" + entity[datastore.KEY].id;
            res.status(200).send(entity).end();
        }
    });
});

// 10. Update a course 
app.patch('/courses/:course_id', async function (req, res, next) {
    var payload = await verify_jwt(req, payload);
    if (!payload) res.status(401).send(errTable[401]).end();
    else {
        // check 403_valid JWT but not admin
        const adminQuery = datastore.createQuery('users').filter(new PropertyFilter('sub', '=', payload.sub));
        datastore.runQuery(adminQuery, (err, entities) => {
            if (entities[0].role !== "admin") res.status(403).send(errTable[403]).end();
            else {
                // check 403_valid JWT but course_id invalid
                const courseKey = datastore.key(['courses', parseInt(req.params.course_id)]);
                datastore.get(courseKey, function (err, courseEntity) {
                    if (courseEntity === undefined) res.status(403).send(errTable[403]).end();
                    else {
                        const instructorKey = datastore.key(['users', parseInt(req.body.instructor_id)]);
                        datastore.get(instructorKey, function (err, instructorEntity) {
                            // check empty req.body or not a recorded id
                            if (instructorEntity === undefined) {
                                courseEntity.id = parseInt(courseEntity[datastore.KEY].id);
                                res.status(200).send(courseEntity).end();
                            }
                            // check 400 instructor_id invalid
                            else if (instructorEntity.role !== "instructor") res.status(400).send(errTable[400]).end();
                            else {
                                // update course
                                courseEntity.instructor_id = req.body.instructor_id;
                                const entity = {
                                    key: courseKey,
                                    data: courseEntity,
                                };
                                datastore.update(entity, (err) => {
                                    datastore.get(courseKey, function (err, entity) {
                                        // Add the id of the new entry that received from Database
                                        const resBody = Object.assign({ id: parseInt(courseKey.path[1]) }, entity);
                                        res.status(200).send(resBody).end();
                                    });
                                });
                            }
                        });
                    }
                });
            }
        });
    }
});

// 11. Delete a course
app.delete('/courses/:course_id', async function (req, res) {
    var payload = await verify_jwt(req, payload);
    if (!payload) return res.status(401).send(errTable[401]).end();
    else {
        // check 403_valid JWT but invalid course_id
        const key = datastore.key(['courses', parseInt(req.params.course_id)]);
        datastore.get(key, function (err, courseEntity) {
            if (!courseEntity) return res.status(403).send(errTable[403]).end();
            else {
                // check 403_valid JWT but not admin
                const adminQuery = datastore.createQuery('users').filter(new PropertyFilter('sub', '=', payload.sub));
                datastore.runQuery(adminQuery, async (err, userEntity) => {
                    if (userEntity[0].role !== "admin") res.status(403).send(errTable[403]).end();
                    else {
                        datastore.delete(key, (err) => {
                            if (err) console.log(err);
                            else res.sendStatus(204);
                        });
                    }
                });
            }
        });
    }
});

async function checkDup(arr1, arr2) {
    for (i in arr1) {
        for (j in arr2) {
            if (arr1[i] === arr2[j]) return false;
        }
    }
    return true;
}

// 12. Update enrollment in a course 
app.patch('/courses/:course_id/students', async function (req, res, next) {
    var payload = await verify_jwt(req, payload);
    if (!payload) res.status(401).send(errTable[401]).end();
    else {
        // check 403_valid JWT but not admin or instrctor
        const adminQuery = datastore.createQuery('users').filter(new PropertyFilter('sub', '=', payload.sub));
        datastore.runQuery(adminQuery, async (err, JWTEntity) => {
            if (JWTEntity[0].role !== "admin" && JWTEntity[0].role !== "instructor") res.status(403).send(errTable[403]).end();
            else {
                // check 403_valid JWT but course_id invalid
                const courseKey = datastore.key(['courses', parseInt(req.params.course_id)]);
                datastore.get(courseKey, async function (err, courseEntity) {
                    if (courseEntity === undefined) res.status(403).send(errTable[403]).end();
                    else {
                        // check 403_instructor_id is valid for this course
                        if (JWTEntity[0].role !== "admin" && courseEntity.instructor_id !== parseInt(JWTEntity[0][datastore.KEY].id))
                            return res.status(403).send(errTable[403]).end();

                        //checks dup in "add" and "remove" list
                        if (await checkDup(req.body.add, req.body.remove) === false)
                            return res.status(409).send(errTable[409]).end();

                        // get all student list
                        const adminQuery = datastore.createQuery('users').filter(new PropertyFilter('role', '=', 'student'));
                        datastore.runQuery(adminQuery, async (err, entities) => {

                            // get an array of student id list
                            var studentIdArr = [];
                            entities.forEach(element => { studentIdArr.push(parseInt(element[datastore.KEY].id)) });
                            // check add and remove list are student only
                            const array3 = req.body.add.concat(req.body.remove);
                            for (i in array3) {
                                if (!studentIdArr.includes(array3[i])) { return res.status(409).send(errTable[409]).end() }
                            }
                            // add "add" list to enrollment 
                            if (req.body.add.length !== 0){
                                if (courseEntity.enrollment) {
                                    courseEntity.enrollment = courseEntity.enrollment.concat(req.body.add);
                                    courseEntity.enrollment = [...new Set(courseEntity.enrollment)];
                                } else courseEntity.enrollment = req.body.add;
                            }

                            // remove "remove" list from enrollment list
                            if (req.body.remove.length !== 0) {
                                if (courseEntity.enrollment) {
                                    var i = courseEntity.enrollment.length
                                    while(i--) {
                                        if (req.body.remove.includes(courseEntity.enrollment[i]))
                                            courseEntity.enrollment.splice(i, 1);
                                    }
                                }
                            }

                            const entity = {
                                key: courseKey,
                                data: courseEntity,
                            };
                            datastore.update(entity, (err) => {
                                if (err) console.log(err);
                                res.status(200).end(); });
                        })
                    }
                });
            }
        });
    }
});

// 13. Get enrollment for a course
app.get("/courses/:course_id/students", async function (req, res) {
    var payload = await verify_jwt(req, payload);
    if (!payload) res.status(401).send(errTable[401]).end();
    else {
        // check 403_valid JWT but not admin or instrctor
        const adminQuery = datastore.createQuery('users').filter(new PropertyFilter('sub', '=', payload.sub));
        datastore.runQuery(adminQuery, async (err, JWTEntity) => {
            if (JWTEntity[0].role !== "admin" && JWTEntity[0].role !== "instructor") res.status(403).send(errTable[403]).end();
            else {
                // check 403_valid JWT but course_id invalid
                const courseKey = datastore.key(['courses', parseInt(req.params.course_id)]);
                datastore.get(courseKey, async function (err, courseEntity) {
                    if (courseEntity === undefined) res.status(403).send(errTable[403]).end();
                    else {
                        // check 403_instructor_id is valid for this course
                        if (JWTEntity[0].role !== "admin" && courseEntity.instructor_id !== parseInt(JWTEntity[0][datastore.KEY].id))
                            return res.status(403).send(errTable[403]).end();
                        return res.status(200).send(courseEntity.enrollment);
                    }
                });
            }
        });
    }
});

app.listen(app.get('port'));
console.log('Express started on local.');