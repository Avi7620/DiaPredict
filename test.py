import os
current_dir = os.path.dirname(__file__)
model_path = os.path.join(current_dir, 'flask', 'model.pkl')
model = pickle.load(open(model_path, 'rb'))
