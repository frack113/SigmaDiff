# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
"""
Project: SigmaDiff.py
Date: 2022/05/14
Author: frack113
Version: 0.0.1
Description: 
    know the rules that have changed between 2 directories
Requirements:
    python :)
Tudo:
    -   all    
"""

import argparse
import pathlib
import sqlite3
from sqlite3 import Error
import hashlib
import base64
import ruamel.yaml
import csv

# Need to be clean
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
            "file_crc": "",
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
        }
        self.sigma_keys = self.sigma.keys()  # run once use many

    def clean_sigma(self):
        for key in self.sigma_keys:
            self.sigma[key] = ""

    def load_sigma_yml(self, sigma_yml, table_name):
        self.clean_sigma()
        path = sigma_yml.parent
        with sigma_yml.open("r", encoding="UTF-8") as file:
            yml_dict = ruamel.yaml.load(file, Loader=ruamel.yaml.RoundTripLoader)
            self.sigma["uuid"] = yml_dict["id"]
            self.sigma["name"] = sigma_yml.name
            self.sigma["path"] = path
            self.sigma["file_crc"] = hashlib.md5(str(yml_dict).encode()).hexdigest()

            self.sigma["title"] = base64.b64encode(yml_dict["title"].encode())
            self.sigma["status"] = (
                base64.b64encode(yml_dict["status"].encode())
                if "status" in yml_dict
                else "-"
            )
            self.sigma["author"] = (
                base64.b64encode(yml_dict["author"].encode())
                if "author" in yml_dict
                else "-"
            )
            self.sigma["description"] = (
                base64.b64encode(yml_dict["description"].encode())
                if "description" in yml_dict
                else "-"
            )
            self.sigma["reference"] = (
                base64.b64encode(str(yml_dict["references"]).encode())
                if "references" in yml_dict
                else "-"
            )
            self.sigma["date"] = (
                base64.b64encode(str(yml_dict["date"]).encode())
                if "date" in yml_dict
                else "-"
            )
            self.sigma["modified"] = (
                base64.b64encode(str(yml_dict["modified"]).encode())
                if "modified" in yml_dict
                else "-"
            )
            self.sigma["falsepositives"] = (
                base64.b64encode(str(yml_dict["falsepositives"]).encode())
                if "falsepositives" in yml_dict
                else "-"
            )
            self.sigma["level"] = (
                base64.b64encode(yml_dict["level"].encode())
                if "level" in yml_dict
                else "-"
            )
            self.sigma["tags"] = (
                base64.b64encode(str(yml_dict["tags"]).encode())
                if "tags" in yml_dict
                else "-"
            )

            self.sigma["logsource"] = base64.b64encode(
                str(yml_dict["logsource"]).encode()
            )
            self.sigma["detection"] = base64.b64encode(
                str(yml_dict["detection"]).encode()
            )

            self.Bdd.add_dico(table_name, self.sigma)

    def load_sigma_folder(self, folder_name, table_name):
        self.Bdd.create_table(table_name, self.sigma, unique=["uuid"], drop=True)

        sigma_list = [yml for yml in pathlib.Path(folder_name).glob("**/*.yml")]
        print(f"Find {len(sigma_list)} file(s)")
        for sigma_file in sigma_list:
            self.load_sigma_yml(sigma_file, table_name)


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
                "update_file": "file_crc",
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

Beta 0.5 :)
"""
)

parser = argparse.ArgumentParser()
parser.add_argument(
    "-o", "--old", help="Your actual Sigma Rules folder", type=str, required=True
)
parser.add_argument(
    "-n", "--new", help="Up to date Sigma Rules folder", type=str, required=True
)
parser.add_argument(
    "-d", "--debug", help="Save database", action='store_true'
)
args = parser.parse_args()

if args.debug :
    Bdd = Sql("SigmaDiff.db")
else:
    Bdd = Sql(":memory:")

sigma_bdd = Sigma(Bdd)


print(f"Check folder : {args.old}")
sigma_bdd.load_sigma_folder(args.old, "old")

print(f"Check folder : {args.new}")
sigma_bdd.load_sigma_folder(args.new, "new")

print("Create the diff table")
result_bdd = Result(Bdd, "old", "new")

result_bdd.check_old()
result_bdd.check_new()


result_bdd.export_csv("SigmaDiff.csv")

print("------------------------------------------")
print("|           Some statistique             |")
print("------------------------------------------")
print(f"Rules remove : {result_bdd.get_nb('file_remove','Y')}")
print(f"Rules add : {result_bdd.get_nb('file_new','Y')}")
print(f"Rules rename : {result_bdd.get_nb('file_rename','Y')}")
print("------------------------------------------")
print("|           More information             |")
print("------------------------------------------")
print(f"Rules update : {result_bdd.get_nb('update_file','Y')}")
print(f"logsource change : {result_bdd.get_nb('update_logsource','Y')}")
print(f"detection change : {result_bdd.get_nb('update_detection','Y')}")
print(f"level change : {result_bdd.get_nb('update_level','Y')}")
print("------------------------------------------")
print("Check SigmaDiff.csv for more details")

Bdd.close()
