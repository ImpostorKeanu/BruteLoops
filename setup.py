import setuptools

# Read README.md as a variable to pass as the package's long
# description
with open('README.md', 'r', encoding='utf-8') as f:
    long_description = f.read()

# Read in all requirements from requirements.txt
with open('requirements.txt', 'r', encoding='utf-8') as f:
    install_requires = [l.strip() for l in f]

setuptools.setup(
    name='bruteloops',
    version='0.0.1',
    author='Justin Angel',
    author_email='justin@arch4ngel.ninja',
    description='A simple password spraying API',
    long_description=long_description,
    long_description_content_type='text/markdown',
    url='https://github.com/arch4ngel/bruteloops',
    include_package_data=True,
    package_data={"": ["*.txt"]},
    packages=setuptools.find_packages(),
    classifiers=[
        'Programming Language :: Python :: 3',
        'License :: OSI Approved :: MIT License',
        'Operating System :: POSIX :: Linux',
    ],
    python_requires='>=3.7',
    scripts=['bl-dbmanager.py','bl-example.py',],
    install_requires=install_requires
)
