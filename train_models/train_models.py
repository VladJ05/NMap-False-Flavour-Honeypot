from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import OneHotEncoder
from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline
from sklearn.metrics import accuracy_score
from pathlib import Path
from joblib import dump
import pandas as pd


def train(protocol, model):
	train_file = Path(__file__).parent.parent / f"resulted_datasets/{protocol}_train.csv"
	test_file = Path(__file__).parent.parent / f"resulted_datasets/{protocol}_test.csv"
	df_train = pd.read_csv(train_file)
	df_test = pd.read_csv(test_file)

	X_train = df_train.drop(columns=["response_type"]).astype(str)
	y_train = df_train["response_type"].astype(str)
	X_test = df_test.drop(columns=["response_type"]).astype(str)
	y_test = df_test["response_type"].astype(str)

	categorical_features = X_train.columns.tolist()

	preprocessor = ColumnTransformer(
		transformers=[
			('cat', OneHotEncoder(handle_unknown='ignore'), categorical_features)
		]
	)

	pipeline = Pipeline([
		('preprocessor', preprocessor),
		('classifier', model)
	])

	pipeline.fit(X_train, y_train)
	# salvarea modelului
	dump_file = Path(__file__).parent.parent / f"resulted_models/{protocol}_model.joblib"
	dump(pipeline, dump_file)

	y_pred = pipeline.predict(X_test)
	return "Accuracy: "  + str(accuracy_score(y_test, y_pred))
	
def train_model(protocol):
	protocol_name = protocol.upper()
	title = f"==== Random Forest {protocol_name} ===="
	print(title)
	accuracy = train(protocol, RandomForestClassifier(n_estimators=100))
	spaces = " " * ((len(title) - len(accuracy)) // 2)
	print(spaces + accuracy)
	print("=" * len(title))
	print("")