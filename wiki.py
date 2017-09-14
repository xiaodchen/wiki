import webapp2, jinja2, os, time, re, hmac, hashlib, random
from string import letters
from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape = True)
secret = 'fart'

def content(): 
	return self.content.replace('\n', '<br>')

def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)

def query(path): 
	if path[0:6] =='/_edit': 
		q = db.GqlQuery("SELECT * FROM Pages WHERE editpath = :path and status_control = 'C'", path= path).get()
	else: 
		q = db.GqlQuery("SELECT * FROM Pages WHERE pagepath = :path and status_control = 'C'", path = path).get()
	return q

def h_query(path): 
	q = list(db.GqlQuery("SELECT * FROM Pages WHERE pagepath = :path ORDER BY created ASC", path = path))
	return q	

def newpage(content, pagepath, editpath, status_control): 
	page = Pages(content = content, pagepath = pagepath, editpath = editpath, status_control = 'C')
	page.put()
	return page.key().id()

def editpage(content, q): 
	if content and q: 
		newpage(content, q.pagepath, q.editpath, 'C')
		q.status_control = None
		q.put()
		return True 
	return False

def make_secure_val(val):
    return '%s|%s' % (val, hmac.new(secret, val).hexdigest())

def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val

def make_salt(length = 5):
    return ''.join(random.choice(letters) for x in xrange(length))

def make_pw_hash(name, pw, salt = None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (salt, h)

def valid_pw(name, password, h):
    salt = h.split(',')[0]
    return h == make_pw_hash(name, password, salt)

def users_key(group = 'default'):
    return db.Key.from_path('users', group)

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE  = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
def valid_email(email):
    return not email or EMAIL_RE.match(email)
class User(db.Model):
    name = db.StringProperty(required = True)
    pw_hash = db.StringProperty(required = True)
    email = db.StringProperty()

    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid, parent = users_key())

    @classmethod
    def by_name(cls, name):
        u = User.all().filter('name =', name).get()
        return u

    @classmethod
    def register(cls, name, pw, email = None):
        pw_hash = make_pw_hash(name, pw)
        return User(parent = users_key(),
                    name = name,
                    pw_hash = pw_hash,
                    email = email)

    @classmethod
    def login(cls, name, pw):
        u = cls.by_name(name)
        if u and valid_pw(name, pw, u.pw_hash):
            return u

class Pages(db.Model):
	editpath = db.StringProperty(required = False)
	pagepath = db.StringProperty(required = False)
	content = db.TextProperty(required = True)
	created = db.DateTimeProperty(auto_now_add = True)
	last_modified = db.DateTimeProperty(auto_now = True)
	status_control = db.StringProperty(required = False)

	def render(self):
		self._render_text = self.content.replace('\n', '<br>')
		print '@@@@@@@', self._render_text 
		return render_str("post.html", p = self)

class WikiHandler(webapp2.RequestHandler): 

	def write(self, *a, **kw): 
		self.response.out.write(*a, **kw)

	def render(self, template, **kw): 
		self.write(self.render_str(template, **kw))

	def render_str(self, template, **params):
		params['user'] = self.user 
		t = jinja_env.get_template(template)
		return t.render(**params)

	def path(self): 
		editpath = self.request.path
		if editpath[0:6] == '/_edit':
			pagepath = editpath[6:]
		elif editpath[0:9] == '/_history': 
			pagepath = editpath[9:]
		else: 
			pagepath = editpath
		if not pagepath: 
			pagepath = '/'
		return editpath, pagepath

	def set_secure_cookie(self, name, val):
		cookie_val = make_secure_val(val)
		self.response.headers.add_header(
			'Set-Cookie',
			'%s=%s; Path=/' % (name, cookie_val))

	def read_secure_cookie(self, name):
		cookie_val = self.request.cookies.get(name)
		return cookie_val and check_secure_val(cookie_val)

	def login(self, user):
		self.set_secure_cookie('user_id', str(user.key().id()))

	def logout(self):
		self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

	def initialize(self, *a, **kw):
		webapp2.RequestHandler.initialize(self, *a, **kw)
		uid = self.read_secure_cookie('user_id')
		self.user = uid and User.by_id(int(uid))

class Signup(WikiHandler):
    def get(self):
        self.render("signup.html")

    def post(self):
        have_error = False
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')
        self.email = self.request.get('email')

        params = dict(username = self.username,
                      email = self.email)

        if not valid_username(self.username):
            params['error_username'] = "That's not a valid username."
            have_error = True

        if not valid_password(self.password):
            params['error_password'] = "That wasn't a valid password."
            have_error = True
        elif self.password != self.verify:
            params['error_verify'] = "Your passwords didn't match."
            have_error = True

        if not valid_email(self.email):
            params['error_email'] = "That's not a valid email."
            have_error = True

        if have_error:
            self.render('signup.html', **params)
        else:
            self.done()

    def done(self, *a, **kw):
        raise NotImplementedError

class Register(Signup):
    def done(self):
        #make sure the user doesn't already exist
        u = User.by_name(self.username)
        if u:
            msg = 'That user already exists.'
            self.render('signup.html', error_username = msg)
        else:
            u = User.register(self.username, self.password, self.email)
            u.put()

            self.login(u)
            self.redirect('/welcome')

class Login(WikiHandler):
    def get(self):
        self.render('login.html')

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')

        u = User.login(username, password)
        if u:
            self.login(u)
            self.redirect('/welcome')
        else:
            msg = 'Invalid login'
            self.render('login.html', error = msg)

class Logout(WikiHandler):
	def get(self):
		self.logout()
		self.redirect(self.request.referer)

class Welcome(WikiHandler):
    def get(self):
        if self.user:
            # self.render('welcome.html', username = self.user.name)
            self.redirect('/')
        else:
            self.redirect('/signup')

class MainPage(WikiHandler): 
	def get(self, *args, **kwargs): 
		originalpath, pagepath = self.path()
		content, allpages = '', ''
		q = query(originalpath)
		if q: 
			q.render()
			content = q._render_text
			#allpages = list(Pages.all().order('-created'))
			self.render('front.html', content=content, allpages = allpages, originalpath = originalpath)
		else: 	
			self.redirect('/_edit%s' % str(originalpath))

class Edit(WikiHandler):
	def get(self, *args, **kwargs): 
		editpath, pagepath = self.path()	
		content = ''
		q = query(editpath)
		if q: 
			q.render()
			content = q._render_text
		self.render('edit.html', content= content, originalpath = pagepath)

	def post(self, *args, **kwargs): 
		editpath, pagepath = self.path()
		content = self.request.get('content')
		if content and editpath: 
			q = query(editpath)
			if q: 
				b = editpage(content, q)
				time.sleep(0.1)
			else: 
				page_id = newpage(content, pagepath, editpath, 'C')
				time.sleep(0.1)
			self.redirect(pagepath)

class History(WikiHandler): 
	def get(self, *a, **kw): 
		originalpath, pagepath = self.path()
		h_pages = h_query(pagepath)
		self.render('history.html', h_pages = h_pages, originalpath = originalpath)

app = webapp2.WSGIApplication([('/', MainPage), 
							   ('/login', Login), 
							   ('/logout', Logout), 
							   ('/welcome', Welcome),
							   ('/signup', Register), 
							   ('/_history/?([a-zA-Z0-9]+)?', History), 
							   ('/_edit/?([a-zA-Z0-9]+)?', Edit),
							   ('/([a-zA-Z0-9]+)', MainPage),
							   ], 
							   debug=True)
