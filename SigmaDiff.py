# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
"""
Project: SigmaDiff.py
Date: 2022/05/xx
Author: frack113
Version: 0.6.0
Description: 
    know the rules that have changed between 2 directories
Requirements:
    python :)
Tudo:
    - diff file
    - correct html ouput
Done:
    - load Sigma file
    - progress bar load file
    - store correct string in db
"""

import argparse
import pathlib
import sqlite3
from sqlite3 import Error
import base64
import ruamel.yaml
import csv
import difflib
from tqdm import tqdm

# Do the sqlite jod
class Sql:
    def __init__(self, where):
        self.dbConnection = self.createConnection(where)
        self.dbHandle = self.dbConnection.cursor()

    def dict_factory(self, cursor, row):
        d = {}
        for idx, col in enumerate(cursor.description):
            d[col[0]] = row[idx]
        return d

    def createConnection(self, db):
        conn = None
        try:
            conn = sqlite3.connect(db)
            conn.row_factory = self.dict_factory  # Allows to get a dict
        except Error as e:
            exit()
        return conn

    def requete(self, sql_requete):
        try:
            self.dbHandle.execute(sql_requete)
            self.dbConnection.commit()
            return True
        except Error as e:
            return False

    def query(self, query):
        try:
            self.dbHandle.execute(query)
            return self.dbHandle.fetchall()
        except Error as e:
            return []

    def create_table(self, name, dico, unique=None, drop=False):
        keys = dico.keys()
        value = ",".join(keys)
        if unique != None:
            for item in unique:
                value = value.replace(item, f"{item} UNIQUE")
        if drop == True:
            query = f"DROP TABLE IF EXISTS {name};"
            self.dbHandle.execute(query)
        query = f"CREATE TABLE IF NOT EXISTS {name} ({value});"
        self.dbHandle.execute(query)
        self.dbConnection.commit()

    def update_by(self, table, dico, name, val):
        keys = list(dico.keys())
        keys.remove(name)
        value = ""
        for item in keys:
            value += f'{item}="{dico[item]}",'
        value = value[:-1]
        query = f'UPDATE {table} SET {value} WHERE {name}="{val}";'
        self.dbHandle.execute(query)

    def add_dico(self, name, dico):
        keys = dico.keys()
        value = ""
        for item in keys:
            value += f'"{dico[item]}",'
        value = value[:-1]
        query = f"INSERT OR REPLACE INTO {name} VALUES ({value});"
        self.dbHandle.execute(query)

    def close(self):
        self.dbConnection.commit()
        self.dbConnection.close()


# todo
class Sigma:
    def __init__(self, Bdd):
        self.Bdd = Bdd
        self.sigma = {
            "uuid": "",
            "name": "",
            "path": "",
            "title": "",
            "status": "",
            "date": "",
            "modified": "",
            "author": "",
            "description": "",
            "reference": "",  # references is a sqlite keyword
            "logsource": "",
            "detection": "",
            "falsepositives": "",
            "level": "",
            "tags": "",
            "file_data": "",
        }
        self.sigma_keys = self.sigma.keys()  # run once use many

    def clean_sigma(self):
        for key in self.sigma_keys:
            self.sigma[key] = ""

    def _to_b64_str_(self,data) -> str:
        byte_64 = base64.b64encode(str(data).encode())
        return byte_64.decode()

    def load_sigma_yml(self, sigma_yml, table_name):
        self.clean_sigma()
        path = sigma_yml.parent
        with sigma_yml.open("r", encoding="UTF-8") as file:
            self.sigma["file_data"] = self._to_b64_str_(file.read())
        with sigma_yml.open("r", encoding="UTF-8") as file:
            yml_dict = ruamel.yaml.load(file, Loader=ruamel.yaml.RoundTripLoader)
            self.sigma["uuid"] = yml_dict["id"]
            self.sigma["name"] = sigma_yml.name
            self.sigma["path"] = path

            self.sigma["title"] = self._to_b64_str_(yml_dict["title"])
            self.sigma["status"] = (
                self._to_b64_str_(yml_dict["status"])
                if "status" in yml_dict
                else "-"
            )
            self.sigma["author"] = (
                self._to_b64_str_(yml_dict["author"])
                if "author" in yml_dict
                else "-"
            )
            self.sigma["description"] = (
                self._to_b64_str_(yml_dict["description"])
                if "description" in yml_dict
                else "-"
            )
            self.sigma["reference"] = (
                self._to_b64_str_(yml_dict["references"])
                if "references" in yml_dict
                else "-"
            )
            self.sigma["date"] = (
                self._to_b64_str_(yml_dict["date"])
                if "date" in yml_dict
                else "-"
            )
            self.sigma["modified"] = (
                self._to_b64_str_(yml_dict["modified"])
                if "modified" in yml_dict
                else "-"
            )
            self.sigma["falsepositives"] = (
                self._to_b64_str_(yml_dict["falsepositives"])
                if "falsepositives" in yml_dict
                else "-"
            )
            self.sigma["level"] = (
                self._to_b64_str_(yml_dict["level"])
                if "level" in yml_dict
                else "-"
            )
            self.sigma["tags"] = (
                self._to_b64_str_(yml_dict["tags"])
                if "tags" in yml_dict
                else "-"
            )

            self.sigma["logsource"] = self._to_b64_str_(yml_dict["logsource"])
            self.sigma["detection"] = self._to_b64_str_(yml_dict["detection"])

            self.Bdd.add_dico(table_name, self.sigma)

    def load_sigma_folder(self, folder_name, table_name):
        self.Bdd.create_table(table_name, self.sigma, unique=["uuid"], drop=True)

        sigma_list = [yml for yml in pathlib.Path(folder_name).glob("**/*.yml")]
        pbar = tqdm(total=len(sigma_list), desc=f"Loading {folder_name}")
        for sigma_file in sigma_list:
            self.load_sigma_yml(sigma_file, table_name)
            pbar.update(1)
        pbar.close()

    def get_diff_id(self,uuid) -> str:
        ret = Bdd.query(f'SELECT file_data FROM old WHERE uuid="{uuid}"')
        ret_b64 = ret[0]['file_data'] if len(ret)>0 else ""
        file_old = base64.b64decode(ret_b64).decode()
        ret = Bdd.query(f'SELECT file_data FROM new WHERE uuid="{uuid}"')
        ret_b64 = ret[0]['file_data'] if len(ret)>0 else ""
        file_new = base64.b64decode(ret_b64).decode()
        diff = difflib.HtmlDiff().make_table(file_old.splitlines(), file_new.splitlines(),context=True)
        return diff

# todo
class Result:
    def __init__(self, Bdd, table_old, table_new):
        self.bdd = Bdd
        self.name_old = table_old
        self.name_new = table_new
        self.table_result = {
            "uuid": "",
            "old_name": "",
            "new_name": "",
            "file_remove": "",
            "file_rename": "",
            "file_new": "",
            "update_file": "",
            "update_title": "",
            "update_status": "",
            "update_date": "",
            "update_modified": "",
            "update_author": "",
            "update_description": "",
            "update_references": "",
            "update_logsource": "",
            "update_detection": "",
            "update_falsepositives": "",
            "update_level": "",
            "update_tags": "",
        }
        self.bdd.create_table("result", self.table_result, unique=["uuid"], drop=True)
        self.table_result_keys = self.table_result.keys()  # run once use many

    def clean_table_result(self):
        for key in self.table_result_keys:
            self.table_result[key] = "N"
        self.table_result["uuid"] = ""
        self.table_result["old_name"] = ""
        self.table_result["new_name"] = ""

    def Udpate_table_result(self):
        ret_new = self.bdd.query(
            f'SELECT * FROM {self.name_new} WHERE uuid = "{self.table_result["uuid"]}";'
        )
        if len(ret_new) > 0:
            data_new = ret_new[0]

            self.table_result["new_name"] = data_new["name"]
            self.table_result["file_rename"] = (
                "N"
                if self.table_result["new_name"] == self.table_result["old_name"]
                else "Y"
            )

            ret_old = self.bdd.query(
                f'SELECT * FROM {self.name_old} WHERE uuid = "{self.table_result["uuid"]}";'
            )
            data_old = ret_old[0]
            diff_check = {
                "update_file": "file_data",
                "update_title": "title",
                "update_status": "status",
                "update_date": "date",
                "update_modified": "modified",
                "update_author": "author",
                "update_description": "description",
                "update_references": "reference",
                "update_logsource": "logsource",
                "update_detection": "detection",
                "update_falsepositives": "falsepositives",
                "update_level": "level",
                "update_tags": "tags",
            }
            for k, v in diff_check.items():
                self.table_result[k] = "N" if data_old[v] == data_new[v] else "Y"

        else:
            self.table_result["file_remove"] = "Y"

        self.bdd.add_dico("result", self.table_result)

    def check_old(self):
        ret_old = self.bdd.query(f"SELECT * FROM {self.name_old};")
        for old_sigma in ret_old:
            self.clean_table_result()
            self.table_result["uuid"] = old_sigma["uuid"]
            self.table_result["old_name"] = old_sigma["name"]
            self.Udpate_table_result()

    def check_new(self):
        ret_new = self.bdd.query(
            f"SELECT * FROM {self.name_new} where uuid NOT IN (SELECT uuid from {self.name_old});"
        )
        for new_sigma in ret_new:
            self.clean_table_result()
            self.table_result["uuid"] = new_sigma["uuid"]
            self.table_result["new_name"] = new_sigma["name"]
            self.table_result["file_new"] = "Y"
            self.bdd.add_dico("result", self.table_result)

    def export_csv(self, name):
        ret_all = self.bdd.query(f"SELECT * FROM result;")
        fieldnames = self.table_result.keys()
        with pathlib.Path(name).open("w", encoding="UTF-8", newline="\n") as csvfile:
            writer = csv.DictWriter(
                csvfile, delimiter=";", quoting=csv.QUOTE_MINIMAL, fieldnames=fieldnames
            )
            writer.writeheader()
            for ligne in ret_all:
                writer.writerow(ligne)

    def get_nb(self, name, status):
        ret_all = self.bdd.query(f'SELECT * FROM result WHERE {name} = "{status}";')
        return len(ret_all)


# Main is the main
print(
    """
   _____ _                       _____  _  __  __ 
  / ____(_)                     |  __ \(_)/ _|/ _|
 | (___  _  __ _ _ __ ___   __ _| |  | |_| |_| |_ 
  \___ \| |/ _` | '_ ` _ \ / _` | |  | | |  _|  _|
  ____) | | (_| | | | | | | (_| | |__| | | | | |  
 |_____/|_|\__, |_| |_| |_|\__,_|_____/|_|_| |_|  
            __/ |                                 
           |___/                                  

Beta 0.6 :)
"""
)

parser = argparse.ArgumentParser()
parser.add_argument(
    "-o", "--old", help="Your actual Sigma Rules folder", type=str, required=True
)
parser.add_argument(
    "-n", "--new", help="Up to date Sigma Rules folder", type=str, required=True
)
parser.add_argument("-d", "--debug", help="Save database", action="store_true")
args = parser.parse_args()

if args.debug:
    Bdd = Sql("SigmaDiff.db")
else:
    Bdd = Sql(":memory:")

sigma_bdd = Sigma(Bdd)

# Load Sigma files
sigma_bdd.load_sigma_folder(args.old, "old")
sigma_bdd.load_sigma_folder(args.new, "new")

print("Calcul the diff table")
result_bdd = Result(Bdd, "old", "new")

result_bdd.check_old()
result_bdd.check_new()


result_bdd.export_csv("SigmaDiff.csv")

mega_str="""
<html>
<head>
    <meta http-equiv="Content-Type"
          content="text/html; charset=utf-8" />
    <title></title>
    <style type="text/css">
        table.diff {font-family:Courier; border:medium;}
        .diff_header {background-color:#e0e0e0}
        td.diff_header {text-align:right}
        .diff_next {background-color:#c0c0c0}
        .diff_add {background-color:#aaffaa}
        .diff_chg {background-color:#ffff77}
        .diff_sub {background-color:#ffaaaa}
    </style>
</head>
<body>
"""

mega_str += f"""
<table>
<tr><th>Information</th><th></th></tr>
<tr><th>Rules remove</th><th>{result_bdd.get_nb('file_remove','Y')}</th></tr>
<tr><th>Rules add</th><th></th>{result_bdd.get_nb('file_new','Y')}</tr>
<tr><th>Rules rename</th><th>{result_bdd.get_nb('file_rename','Y')}</th></tr>
<tr><th>Rules update</th><th>{result_bdd.get_nb('update_file','Y')}</th></tr>
<tr><th>logsource change</th><th>{result_bdd.get_nb('update_logsource','Y')}</th></tr>
<tr><th>detection change</th><th>{result_bdd.get_nb('update_detection','Y')}</th></tr>
<tr><th>level change</th><th>{result_bdd.get_nb('update_level','Y')}</th></tr>
</table>
<BR>
"""


list_uuid = Bdd.query('SELECT DISTINCT uuid,new_name FROM result WHERE update_logsource ="Y" OR update_logsource= "Y" OR update_level="Y";')
if len(list_uuid)>0:
    for uuid_dict in list_uuid:
        mega_str += f'File : {uuid_dict["new_name"]}<BR>'
        mega_str += sigma_bdd.get_diff_id(uuid_dict['uuid'])
        mega_str += "<BR>"

mega_str += "</body></html>"
with pathlib.Path('SigmaDiff.html').open('w',encoding='UTF-8') as file:
    file.write(mega_str)

Bdd.close()
print("Check SigmaDiff.csv or SigmaDiff.html for more details")
