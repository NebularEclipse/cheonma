import unittest

ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif"}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

class Test_allowed_file(unittest.TestCase):
    def test_png(self):
        self.assertEqual(allowed_file('test.png'), True)

    def test_jpg(self):
        self.assertEqual(allowed_file('test.jpg'), True)

    def test_gif(self):
        self.assertEqual(allowed_file('test.gif'), True)

if __name__ == "__main__":
    unittest.main()