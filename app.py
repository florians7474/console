from flask import Flask, render_template

app = Flask(__name__)

# Un seul mode actif a la fois. None = tout est arrete.
etat = {"mode_actif": None}

@app.route("/")
def accueil():
    return render_template("home.html", actif=etat["mode_actif"])

@app.route("/pwnagotchi")
def pwnagotchi():
    return "<h1 style='color:white;background:#0d1117;font-family:sans-serif'>Pwnagotchi<br><a style='color:#58a6ff' href='/'>&larr; Retour</a></h1>"

@app.route("/cassage")
def cassage():
    return "<h1 style='color:white;background:#0d1117;font-family:sans-serif'>Cassage<br><a style='color:#58a6ff' href='/'>&larr; Retour</a></h1>"

@app.route("/bjorn")
def bjorn():
    return "<h1 style='color:white;background:#0d1117;font-family:sans-serif'>Bjorn<br><a style='color:#58a6ff' href='/'>&larr; Retour</a></h1>"

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
